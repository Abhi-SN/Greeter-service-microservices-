package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var dbpool *pgxpool.Pool // pointer variable that manages a pool of PostgreSQL database connections in Go.

var jwtKey = []byte("my_super_secret_key")

type Credetials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

func initDB() {
	var err error
	connStr := "postgres://myuser:mypassword@db:5432/mydb?sslmode=disable"

	for i := 0; i < 5; i++ {
		dbpool, err = pgxpool.New(context.Background(), connStr)
		if err == nil {
			if err = dbpool.Ping(context.Background()); err == nil {
				log.Println("Auth-Service; Successfully connected to PostgreSQL!")
				break
			}
		}
		log.Printf("Auth service could not connect to db, retying in (%v)", err)
		time.Sleep(5 * time.Second)
	}
	if dbpool == nil {
		log.Fatalf("Auth-Service failed to connect to database")

	}
	_, err = dbpool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL
		);
	`)

	if err != nil {
		log.Fatalf("Auth-Service: Unable to create  table %v", err)
	}

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credetials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = dbpool.Exec(context.Background(),
		"INSERT INTO users(username, password_hash) VALUES ($1, $2)",
		creds.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, "Could not register user (username may already exists)", http.StatusInternalServerError)
		log.Printf("DB error: %v", err)
		return
	}

	profileData := map[string]string{
		"username":  creds.Username,
		"full_name": creds.FullName,
		"email":     creds.Email,
	}
	jsonData, _ := json.Marshal(profileData)

	resp, err := http.Post("http://user-service:8080/profiles", "application/json", bytes.NewBuffer(jsonData))
	if err != nil || resp.StatusCode != http.StatusCreated {
		log.Printf("Auth-Service: Failed to create user profile for %s. Status : %S, Error : %v", creds.Username, resp.Status, err)
	} else {
		log.Printf("Auth service: Successfully Created user profile for %s", creds.Username)
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credetials

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var storedHash string
	err := dbpool.QueryRow(context.Background(),
		"SELECT password_hash FROM users WHERE username= $1", creds.Username).Scan(&storedHash)
	if err != nil {
		http.Error(w, "Unauthorized: User not found", http.StatusUnauthorized)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Unauthorized: Invalid password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &jwt.RegisteredClaims{
		Subject:   creds.Username,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origins", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	initDB()
	defer dbpool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)

	// Configure CORS using the rs/cors library
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Allow any origin
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut, http.MethodOptions},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	// Create a handler that applies the CORS middleware to our router
	handler := c.Handler(mux)

	log.Println("Auth-Service: Starting on port 8080...")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
