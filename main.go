package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret = []byte("super-secret-key")

// Rate limiter - track login/register attempts per IP
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var limiter = &RateLimiter{
	attempts: make(map[string][]time.Time),
}

// Check if IP is rate limited (max 5 attempts per 15 minutes)
func (rl *RateLimiter) IsLimited(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window := 15 * time.Minute

	// Get attempts for this IP
	attempts := rl.attempts[ip]

	// Remove old attempts outside the window
	var recentAttempts []time.Time
	for _, t := range attempts {
		if now.Sub(t) < window {
			recentAttempts = append(recentAttempts, t)
		}
	}

	// Update stored attempts
	rl.attempts[ip] = recentAttempts

	// Check if limited (5 attempts per 15 min)
	if len(recentAttempts) >= 5 {
		return true
	}

	// Record this new attempt
	rl.attempts[ip] = append(recentAttempts, now)
	return false
}

// Get client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func init() {
	// Load .env file
	godotenv.Load()

	var err error
	db, err = sql.Open("sqlite3", "./auth.db")
	if err != nil {
		log.Fatal(err)
	}

	initDB()
}

// Sanitize user input - trim whitespace and validate format
func sanitizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("email cannot be empty")
	}
	if len(email) > 254 {
		return "", fmt.Errorf("email too long")
	}
	if !strings.Contains(email, "@") {
		return "", fmt.Errorf("invalid email format")
	}
	return email, nil
}

// Sanitize password - trim whitespace and validate minimum length
func sanitizePassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if len(password) < 6 {
		return "", fmt.Errorf("password must be at least 6 characters")
	}
	if len(password) > 128 {
		return "", fmt.Errorf("password too long")
	}
	return password, nil
}

// Sanitize 2FA code - must be 6 digits
func sanitizeCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return "", fmt.Errorf("code must be 6 digits")
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("code must contain only digits")
		}
	}
	return code, nil
}

func main() {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/register", corsMiddleware(register))
	http.HandleFunc("/api/login", corsMiddleware(login))
	http.HandleFunc("/api/verify-2fa", corsMiddleware(verify2FA))
	http.HandleFunc("/api/logout", corsMiddleware(logout))

	port := ":3000"
	if p := os.Getenv("PORT"); p != "" {
		port = ":" + p
	}

	log.Printf("Server running on %s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func initDB() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		two_fa_code TEXT,
		two_fa_expires INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Database initialization error:", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Rate limiting
	clientIP := getClientIP(r)
	if limiter.IsLimited(clientIP) {
		json.NewEncoder(w).Encode(map[string]string{"error": "Too many registration attempts. Try again in 15 minutes."})
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Sanitize inputs
	email, err := sanitizeEmail(email)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	password, err = sanitizePassword(password)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Error hashing password"})
		return
	}

	_, err = db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", email, hashedPassword)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Email already exists"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Registered successfully"})
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Rate limiting
	clientIP := getClientIP(r)
	if limiter.IsLimited(clientIP) {
		json.NewEncoder(w).Encode(map[string]string{"error": "Too many login attempts. Try again in 15 minutes."})
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Parse both form-urlencoded and multipart form data
	r.ParseForm()
	r.ParseMultipartForm(10 << 20) // 10MB max
	
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Sanitize inputs
	email, err := sanitizeEmail(email)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	password, err = sanitizePassword(password)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var user User
	var hashedPassword string
	err = db.QueryRow("SELECT email, password FROM users WHERE email = ?", email).
		Scan(&user.Email, &hashedPassword)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Generate 6-digit 2FA code
	code := generate2FACode()
	expiresAt := time.Now().Add(10 * time.Minute).Unix()

	// Store code in database
	_, err = db.Exec("UPDATE users SET two_fa_code = ?, two_fa_expires = ? WHERE email = ?", 
		code, expiresAt, email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Error generating code"})
		return
	}

	// Send email in background (non-blocking)
	go sendEmail(email, code)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA code sent to email"})
}

func verify2FA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	email := r.FormValue("email")
	code := r.FormValue("code")

	// Sanitize inputs
	email, err := sanitizeEmail(email)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	code, err = sanitizeCode(code)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var storedCode string
	var expiresAt int64
	err = db.QueryRow("SELECT two_fa_code, two_fa_expires FROM users WHERE email = ?", email).
		Scan(&storedCode, &expiresAt)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid email"})
		return
	}

	// Check if code expired
	if time.Now().Unix() > expiresAt {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Code expired"})
		return
	}

	// Check if code matches
	if code != storedCode {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid code"})
		return
	}

	// Clear the code
	_, err = db.Exec("UPDATE users SET two_fa_code = NULL, two_fa_expires = NULL WHERE email = ?", email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Error updating user"})
		return
	}

	// Generate JWT token
	token := generateToken(email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func generateToken(email string) string {
	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)
	return tokenString
}

func validateToken(tokenString string) (string, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	return claims.Email, nil
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Recover from panics in handlers so the whole server doesn't die
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered in handler %s %s: %v", r.Method, r.URL.Path, rec)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			}
		}()

		// Basic CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next(w, r)
	})
}

func generate2FACode() string {
	b := make([]byte, 3)
	rand.Read(b)
	num := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", num%1000000)
}

func sendEmail(toEmail, code string) error {
	// Get SMTP config from .env
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpFrom := os.Getenv("SMTP_FROM")

	// If env vars not set, log and return error
	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPassword == "" {
		err := fmt.Errorf("SMTP credentials not configured in .env")
		log.Printf("Email error: %v", err)
		return err
	}

	to := []string{toEmail}
	subject := "Subject: Your 2FA Code\r\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n"
	body := fmt.Sprintf(`<html><body><h2>Your 2FA Code</h2><p><strong>%s</strong></p><p>This code expires in 10 minutes.</p></body></html>`, code)

	message := subject + mime + "\r\n" + body

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)
	addr := smtpHost + ":" + smtpPort

	log.Printf("Sending 2FA code to %s via %s:%s", toEmail, smtpHost, smtpPort)
	err := smtp.SendMail(addr, auth, smtpFrom, to, []byte(message))
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return err
	}

	log.Printf("2FA code sent successfully to %s", toEmail)
	return nil
}