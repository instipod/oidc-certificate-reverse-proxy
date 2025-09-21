package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config represents the JSON configuration structure
type Config struct {
	Server struct {
		Port     string `json:"port"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"server"`
	Upstream struct {
		URL      string `json:"url"`
		Insecure bool   `json:"insecure"`
	} `json:"upstream"`
	OIDC struct {
		IssuerURL    string   `json:"issuer_url"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURL  string   `json:"redirect_url"`
		Scopes       []string `json:"scopes"`
	} `json:"oidc"`
	CA struct {
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"ca_key"`
	} `json:"ca"`
	Security struct {
		CookieSecret      string `json:"cookie_secret"`
		SessionExpiry     string `json:"session_expiry"` // Duration string like "24h", "30m"
		CertificateExpiry string `json:"certificate_expiry"`
	} `json:"security"`
}

// ProxyServer represents the main proxy server
type ProxyServer struct {
	config            *Config
	oauth2Config      *oauth2.Config
	verifier          *oidc.IDTokenVerifier
	caCert            *x509.Certificate
	caKey             *rsa.PrivateKey
	sessions          map[string]*Session
	sessionMutex      sync.RWMutex
	cookieSecret      []byte
	sessionExpiry     time.Duration
	certificateExpiry time.Duration
	// New fields for certificate caching
	certCache      map[string]*tls.Certificate
	certCacheMutex sync.RWMutex
}

// Session represents a user session
type Session struct {
	Username  string                 `json:"username"`
	Token     *oauth2.Token          `json:"token"`
	Claims    map[string]interface{} `json:"claims"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// EncryptedCookie represents the structure stored in encrypted cookies
type EncryptedCookie struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// loadConfig loads configuration from JSON file
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Set defaults
	if config.Server.Port == "" {
		config.Server.Port = "8443"
	}
	if len(config.OIDC.Scopes) == 0 {
		config.OIDC.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if config.CA.CertFile == "" {
		config.CA.CertFile = "ca.crt"
	}
	if config.CA.KeyFile == "" {
		config.CA.KeyFile = "ca.key"
	}
	if config.Security.CookieSecret == "" {
		return nil, fmt.Errorf("security.cookie_secret is required in configuration")
	}
	if config.Security.SessionExpiry == "" {
		config.Security.SessionExpiry = "24h" // Default 24 hours
	}
	if config.Security.CertificateExpiry == "" {
		config.Security.CertificateExpiry = "1h" // Default 1 hour
	}

	return &config, nil
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config *Config) (*ProxyServer, error) {
	ctx := context.Background()

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, config.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     config.OIDC.ClientID,
		ClientSecret: config.OIDC.ClientSecret,
		RedirectURL:  config.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.OIDC.Scopes,
	}

	// Configure ID token verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: config.OIDC.ClientID})

	// Parse session expiry
	sessionExpiry, err := time.ParseDuration(config.Security.SessionExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid session_expiry format: %w", err)
	}

	// Parse certificate expiry
	certificateExpiry, err := time.ParseDuration(config.Security.CertificateExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate_expiry format: %w", err)
	}

	// Prepare cookie secret (must be 32 bytes for AES-256)
	cookieSecret := []byte(config.Security.CookieSecret)
	if len(cookieSecret) < 32 {
		// Pad with zeros if too short
		padded := make([]byte, 32)
		copy(padded, cookieSecret)
		cookieSecret = padded
	} else if len(cookieSecret) > 32 {
		// Truncate if too long
		cookieSecret = cookieSecret[:32]
	}

	proxy := &ProxyServer{
		config:            config,
		oauth2Config:      oauth2Config,
		verifier:          verifier,
		sessions:          make(map[string]*Session),
		cookieSecret:      cookieSecret,
		sessionExpiry:     sessionExpiry,
		certificateExpiry: certificateExpiry,
		certCache:         make(map[string]*tls.Certificate),
		certCacheMutex:    sync.RWMutex{},
	}

	// Generate or load CA certificate
	if err := proxy.ensureCA(); err != nil {
		return nil, fmt.Errorf("failed to ensure CA: %w", err)
	}

	// Start session cleanup routine
	go proxy.cleanupExpiredSessions()

	return proxy, nil
}

// handleProxy handles the main proxy functionality
func (p *ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Skip auth for auth endpoints
	if strings.HasPrefix(r.URL.Path, "/auth/") {
		http.NotFound(w, r)
		return
	}

	// Check authentication
	session := p.getSession(r)
	if session == nil {
		// Redirect to login with current path as redirect parameter
		loginURL := fmt.Sprintf("/auth/login?redirect=%s", url.QueryEscape(r.URL.RequestURI()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Additional check: verify OAuth2 token expiry (separate from session expiry)
	if session.Token != nil && !session.Token.Expiry.IsZero() && session.Token.Expiry.Before(time.Now()) {
		// OAuth2 token expired, remove session and redirect to login
		log.Printf("OAuth2 token expired for user %s", session.Username)

		// Clean up expired session
		cookieData, err := p.getEncryptedCookie(r)
		if err == nil {
			p.sessionMutex.Lock()
			delete(p.sessions, cookieData.SessionID)
			p.sessionMutex.Unlock()
		}

		loginURL := fmt.Sprintf("/auth/login?redirect=%s", url.QueryEscape(r.URL.RequestURI()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Determine the remaining validity period for the client certificate
	// This will be the minimum of the session expiry and the OAuth token expiry
	sessionRemaining := time.Until(session.ExpiresAt)
	tokenRemaining := time.Until(session.Token.Expiry)

	validity := sessionRemaining
	if tokenRemaining < validity {
		validity = tokenRemaining
	}
	if validity > p.certificateExpiry {
		// Limit the certificate validity to max specific, or shorter if the token/session says so
		validity = p.certificateExpiry
	}

	// Generate or retrieve client certificate for upstream authentication
	clientCert, err := p.generateClientCert(session, validity)
	if err != nil {
		http.Error(w, "Failed to generate client certificate", http.StatusInternalServerError)
		log.Printf("Client cert generation error: %v", err)
		return
	}

	// Parse upstream URL
	upstreamURL, err := url.Parse(p.config.Upstream.URL)
	if err != nil {
		http.Error(w, "Invalid upstream URL", http.StatusInternalServerError)
		log.Printf("Upstream URL parse error: %v", err)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// Configure transport with client certificate
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			// FIX: Dereference the pointer here
			Certificates:       []tls.Certificate{*clientCert},
			InsecureSkipVerify: p.config.Upstream.Insecure,
		},
	}

	// Modify request to add authenticated user header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Authentication headers
		req.Header.Set("X-Authenticated-User", session.Username)

		// Add other useful headers
		if email, ok := session.Claims["email"].(string); ok {
			req.Header.Set("X-Authenticated-Email", email)
		}
		if name, ok := session.Claims["name"].(string); ok {
			req.Header.Set("X-Authenticated-Name", name)
		}

		// Add session info headers
		req.Header.Set("X-Session-Expires", session.ExpiresAt.Format(time.RFC3339))
	}

	// Log the request
	log.Printf("proxy: %s: %s %s (session expires: %s)",
		session.Username, r.Method, r.URL.Path, session.ExpiresAt.Format(time.RFC3339))

	// Serve the request
	proxy.ServeHTTP(w, r)
}

// cleanupExpiredSessions runs periodically to remove expired sessions from memory
func (p *ProxyServer) cleanupExpiredSessions() {
	ticker := time.NewTicker(15 * time.Minute) // Cleanup every 15 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			var expiredSessions []string

			p.sessionMutex.RLock()
			for sessionID, session := range p.sessions {
				if now.After(session.ExpiresAt) {
					expiredSessions = append(expiredSessions, sessionID)
				}
			}
			p.sessionMutex.RUnlock()

			if len(expiredSessions) > 0 {
				p.sessionMutex.Lock()
				for _, sessionID := range expiredSessions {
					if session, exists := p.sessions[sessionID]; exists {
						log.Printf("Cleaning up expired session for user: %s", session.Username)
						delete(p.sessions, sessionID)
					}
				}
				p.sessionMutex.Unlock()

				log.Printf("Cleaned up %d expired sessions", len(expiredSessions))
			}

			// Clean up expired certificates from cache
			p.certCacheMutex.Lock()
			for username, cert := range p.certCache {
				if time.Now().After(cert.Leaf.NotAfter) {
					log.Printf("Cleaning up expired client certificate for user: %s", username)
					delete(p.certCache, username)
				}
			}
			p.certCacheMutex.Unlock()
		}
	}
}

// ensureCA generates a CA certificate if it doesn't exist
func (p *ProxyServer) ensureCA() error {
	// Try to load existing CA
	if _, err := os.Stat(p.config.CA.CertFile); err == nil {
		if _, err := os.Stat(p.config.CA.KeyFile); err == nil {
			return p.loadCA()
		}
	}

	log.Println("Generating new CA certificate...")
	return p.generateCA()
}

// loadCA loads existing CA certificate and key
func (p *ProxyServer) loadCA() error {
	certPEM, err := os.ReadFile(p.config.CA.CertFile)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(p.config.CA.KeyFile)
	if err != nil {
		return fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate")
	}

	p.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key")
	}

	p.caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA key: %w", err)
	}

	log.Println("Loaded existing CA certificate")
	return nil
}

// generateCA generates a new CA certificate and key
func (p *ProxyServer) generateCA() error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Reverse Proxy CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(p.config.CA.CertFile)
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encoding certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(p.config.CA.KeyFile)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}

	p.caCert = caCert
	p.caKey = caKey

	log.Printf("Generated new CA certificate: %s", p.config.CA.CertFile)
	return nil
}

// generateClientCert generates a short-lived client certificate for a user
// It caches the certificate in memory and reuses it if not expired.
func (p *ProxyServer) generateClientCert(session *Session, validity time.Duration) (*tls.Certificate, error) {
	p.certCacheMutex.RLock()
	cachedCert, found := p.certCache[session.Username]
	p.certCacheMutex.RUnlock()

	// Check if cached certificate is still valid
	if found && cachedCert.Leaf.NotAfter.After(time.Now()) {
		return cachedCert, nil
	}

	// If not found or expired, generate a new one
	log.Printf("Generating new certificate for user %s...", session.Username)

	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating client key: %w", err)
	}

	hasher := sha512.New()
	hasher.Write([]byte(session.Username))
	dateStr := time.Now().Format(time.RFC3339Nano)
	hasher.Write([]byte(dateStr))
	hashBytes := hasher.Sum(nil)
	bi := new(big.Int)
	bi.SetBytes(hashBytes)

	// Create client certificate template
	template := x509.Certificate{
		SerialNumber: bi,
		Subject: pkix.Name{
			CommonName: session.Username,
		},
		NotBefore:   time.Now().Add(time.Second * 2),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if email, ok := session.Claims["email"].(string); ok {
		template.EmailAddresses = append(template.EmailAddresses, email)
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &clientKey.PublicKey, p.caKey)
	if err != nil {
		return nil, fmt.Errorf("creating client certificate: %w", err)
	}

	// Parse the newly created certificate for its validity period
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing new client certificate: %w", err)
	}

	// Create TLS certificate
	newCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  clientKey,
		Leaf:        leafCert,
	}

	// Cache the new certificate
	p.certCacheMutex.Lock()
	p.certCache[session.Username] = newCert
	p.certCacheMutex.Unlock()

	log.Printf("New certificate for user %s: Serial %s (expires %s)", session.Username, bi.String(), time.Now().Add(validity).Format(time.RFC3339))

	return newCert, nil
}

// encryptCookie encrypts cookie data using AES-GCM
func (p *ProxyServer) encryptCookie(data []byte) (string, error) {
	block, err := aes.NewCipher(p.cookieSecret)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// decryptCookie decrypts cookie data using AES-GCM
func (p *ProxyServer) decryptCookie(encrypted string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(p.cookieSecret)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// setEncryptedCookie sets an encrypted cookie with session information
func (p *ProxyServer) setEncryptedCookie(w http.ResponseWriter, sessionID, username string, expiresAt time.Time) error {
	cookieData := EncryptedCookie{
		SessionID: sessionID,
		Username:  username,
		ExpiresAt: expiresAt,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		return fmt.Errorf("marshaling cookie data: %w", err)
	}

	encrypted, err := p.encryptCookie(jsonData)
	if err != nil {
		return fmt.Errorf("encrypting cookie: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    encrypted,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(p.sessionExpiry.Seconds()),
		Path:     "/",
	})

	return nil
}

// getEncryptedCookie retrieves and decrypts session information from cookie
func (p *ProxyServer) getEncryptedCookie(r *http.Request) (*EncryptedCookie, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	decrypted, err := p.decryptCookie(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("decrypting cookie: %w", err)
	}

	var cookieData EncryptedCookie
	if err := json.Unmarshal(decrypted, &cookieData); err != nil {
		return nil, fmt.Errorf("unmarshaling cookie data: %w", err)
	}

	// Check if cookie has expired
	if time.Now().After(cookieData.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return &cookieData, nil
}

// Start starts the proxy server
func (p *ProxyServer) Start() error {
	mux := http.NewServeMux()

	// OIDC endpoints
	mux.HandleFunc("/auth/login", p.handleLogin)
	mux.HandleFunc("/auth/callback", p.handleCallback)
	mux.HandleFunc("/auth/logout", p.handleLogout)

	// Proxy handler
	mux.HandleFunc("/", p.handleProxy)

	server := &http.Server{
		Addr:    ":" + p.config.Server.Port,
		Handler: mux,
	}

	log.Printf("Starting proxy server on port %s", p.config.Server.Port)

	// If TLS cert/key files are specified, use them
	if p.config.Server.CertFile != "" && p.config.Server.KeyFile != "" {
		return server.ListenAndServeTLS(p.config.Server.CertFile, p.config.Server.KeyFile)
	}

	// Otherwise, generate a self-signed certificate for the server
	cert, err := p.generateServerCert()
	if err != nil {
		return fmt.Errorf("generating server certificate: %w", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return server.ListenAndServeTLS("", "")
}

// generateServerCert generates a self-signed server certificate
func (p *ProxyServer) generateServerCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating server key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Reverse Proxy Server"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating server certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// handleLogin redirects to OIDC provider
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Capture the original URL for redirect after authentication
	redirectTo := r.URL.Query().Get("redirect")
	if redirectTo == "" {
		redirectTo = r.Header.Get("Referer")
		if redirectTo == "" || strings.Contains(redirectTo, "/auth/") {
			redirectTo = "/"
		}
	}

	state := fmt.Sprintf("%d", time.Now().UnixNano())

	// Store both state and redirect URL in session cookie
	stateData := fmt.Sprintf("%s|%s", state, redirectTo)

	url := p.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// Store state in session cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    stateData,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback processes OIDC callback
func (p *ProxyServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	// Parse state data (state|redirect)
	stateParts := strings.SplitN(stateCookie.Value, "|", 2)
	if len(stateParts) != 2 {
		http.Error(w, "Invalid state cookie format", http.StatusBadRequest)
		return
	}

	expectedState := stateParts[0]
	redirectTo := stateParts[1]

	if expectedState != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	// Exchange code for token
	oauth2Token, err := p.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	idToken, err := p.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		log.Printf("ID token verification error: %v", err)
		return
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		log.Printf("Claims extraction error: %v", err)
		return
	}

	// Get preferred username
	username, ok := claims["preferred_username"].(string)
	if !ok {
		// Fallback to email or sub
		if email, ok := claims["email"].(string); ok {
			username = email
		} else if sub, ok := claims["sub"].(string); ok {
			username = sub
		} else {
			username = "unknown"
		}
	}

	// Create session with configurable expiry
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	expiresAt := time.Now().Add(p.sessionExpiry)

	session := &Session{
		Username:  username,
		Token:     oauth2Token,
		Claims:    claims,
		ExpiresAt: expiresAt,
	}

	p.sessionMutex.Lock()
	p.sessions[sessionID] = session
	p.sessionMutex.Unlock()

	// Set encrypted session cookie
	if err := p.setEncryptedCookie(w, sessionID, username, expiresAt); err != nil {
		http.Error(w, "Failed to set session cookie", http.StatusInternalServerError)
		log.Printf("Cookie encryption error: %v", err)
		return
	}

	log.Printf("User %s authenticated successfully (expires: %s)", username, expiresAt.Format(time.RFC3339))

	// Avoid redirect loops by ensuring we don't redirect to auth endpoints
	if strings.HasPrefix(redirectTo, "/auth/") {
		redirectTo = "/"
	}

	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// handleLogout clears session
func (p *ProxyServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Try to get session from encrypted cookie
	cookieData, err := p.getEncryptedCookie(r)
	if err == nil {
		// Remove session from memory
		p.sessionMutex.Lock()
		delete(p.sessions, cookieData.SessionID)
		p.sessionMutex.Unlock()
		log.Printf("User %s logged out", cookieData.Username)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		Path:     "/",
	})

	fmt.Fprintf(w, "Logged out successfully")
}

// getSession retrieves session from encrypted cookie and validates it
func (p *ProxyServer) getSession(r *http.Request) *Session {
	cookieData, err := p.getEncryptedCookie(r)
	if err != nil {
		// Cookie is invalid, expired, or doesn't exist
		return nil
	}

	p.sessionMutex.RLock()
	session, exists := p.sessions[cookieData.SessionID]
	p.sessionMutex.RUnlock()

	if !exists {
		// Session doesn't exist in memory (server restart, cleanup, etc.)
		return nil
	}

	// Check if session has expired (double check against both cookie and session)
	now := time.Now()
	if now.After(session.ExpiresAt) || now.After(cookieData.ExpiresAt) {
		// Clean up expired session
		p.sessionMutex.Lock()
		delete(p.sessions, cookieData.SessionID)
		p.sessionMutex.Unlock()
		return nil
	}

	// Verify that cookie username matches session username (integrity check)
	if session.Username != cookieData.Username {
		log.Printf("Session integrity check failed: cookie username %s != session username %s",
			cookieData.Username, session.Username)
		// Clean up potentially compromised session
		p.sessionMutex.Lock()
		delete(p.sessions, cookieData.SessionID)
		p.sessionMutex.Unlock()
		return nil
	}

	return session
}
