// UPDATED FILE
// Replaced the custom CORS middleware with the standard 'rs/cors' library for robustness.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors" // NEW: Import the cors library
)

var jwtKey = []byte("my_super_secret_key")

type UserProfile struct {
	FullName string `json:"full_name"`
}

// greetHandler
func greetHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	username := claims.Subject

	profileURL := fmt.Sprintf("http://user-service:8080/profiles/%s", username)
	resp, err := http.Get(profileURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("Greeter-Service: Could not fetch profile for %s. Status: %s, Error: %v", username, resp.Status, err)
		greeting := fmt.Sprintf("Hello, %s! Welcome.", username)
		w.Write([]byte(greeting))
		return
	}
	defer resp.Body.Close()

	var profile UserProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		log.Printf("Greeter-Service: Could not decode profile for %s: %v", username, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	greeting := fmt.Sprintf("Hello, %s! It's great to see you.", profile.FullName)
	w.Write([]byte(greeting))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/greet", greetHandler)

	// Configure CORS using the rs/cors library
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut, http.MethodOptions},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	// Create a handler that applies the CORS middleware to our router
	handler := c.Handler(mux)

	log.Println("Greeter-Service: Starting on port 8080...")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
