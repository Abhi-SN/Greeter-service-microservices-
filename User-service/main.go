// NEW FILE
// This is the Go code for our new user profile service.

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var dbpool *pgxpool.Pool

// UserProfile struct for our user data
type UserProfile struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

// initDB connects to the database and creates the user_profiles table
func initDB() {
	var err error
	connStr := "postgres://myuser:mypassword@db:5432/mydb?sslmode=disable"

	for i := 0; i < 5; i++ {
		dbpool, err = pgxpool.New(context.Background(), connStr)
		if err == nil {
			if err = dbpool.Ping(context.Background()); err == nil {
				log.Println("User-Service: Successfully connected to PostgreSQL!")
				break
			}
		}
		log.Printf("User-Service: Could not connect to db, retrying... (%v)", err)
		time.Sleep(5 * time.Second)
	}

	if dbpool == nil {
		log.Fatalf("User-Service: Could not establish a connection to the database.")
	}

	// Create table for user profiles if it doesn't exist
	_, err = dbpool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS user_profiles (
			id SERIAL PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			full_name TEXT,
			email TEXT
		);
	`)
	if err != nil {
		log.Fatalf("User-Service: Unable to create table: %v", err)
	}
}

// createProfileHandler handles creating a new user profile
func createProfileHandler(w http.ResponseWriter, r *http.Request) {
	var profile UserProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	_, err := dbpool.Exec(context.Background(),
		"INSERT INTO user_profiles (username, full_name, email) VALUES ($1, $2, $3)",
		profile.Username, profile.FullName, profile.Email)

	if err != nil {
		http.Error(w, "Could not create user profile", http.StatusInternalServerError)
		log.Printf("DB error: %v", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User profile created successfully!"))
}

// getProfileHandler retrieves a user profile by username
func getProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Path will be /profiles/{username}
	username := strings.TrimPrefix(r.URL.Path, "/profiles/")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	var profile UserProfile
	err := dbpool.QueryRow(context.Background(),
		"SELECT id, username, full_name, email FROM user_profiles WHERE username=$1", username).Scan(&profile.ID, &profile.Username, &profile.FullName, &profile.Email)

	if err != nil {
		http.Error(w, "User profile not found", http.StatusNotFound)
		log.Printf("DB error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func main() {
	initDB()
	defer dbpool.Close()

	http.HandleFunc("/profiles", createProfileHandler) // POST
	http.HandleFunc("/profiles/", getProfileHandler)   // GET /profiles/{username}

	log.Println("User-Service: Starting on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
