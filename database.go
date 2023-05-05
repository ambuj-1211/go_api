package main

import (
	"fmt"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func database() {
	hash, err := bcrypt.GenerateFromPassword([]byte("password3"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	fmt.Println(hash)
	// Set up database connection parameters
	// dbname := "mydb"
	// dbuser := "postgres"
	// dbpassword := "linuxislove"
	// dbhost := "localhost"
	// dbport := "5432"
	// sslmode := "disable"

	// // Create database connection string
	// connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
	// 	dbhost, dbport, dbuser, dbpassword, dbname, sslmode)

	// // Open database connection
	// db, err := sql.Open("postgres", connStr)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer db.Close()

	// var hashedPassword string
	//access the database with username to get the password
	// err = db.QueryRow("SELECT password FROM users WHERE username = ", credentials.Username).Scan(&hashedPassword)
	// if err != nil {
	// 	panic(err)
	// }
	// Insert new user and password into "users" table
	// username := "user1"
	// password := "password"
	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	// if err != nil {
	// 	panic(err)
	// }
	// // hashedPassword := "hashedpassword" // replace with your own hashing function
	// _, err = db.Exec(`CREATE TABLE users (username VARCHAR(50) UNIQUE NOT NULL,
	// password TEXT NOT NULL);`)
	// insertQuery := fmt.Sprintf("INSERT INTO users (username, password) VALUES ('%s', '%s');",
	// 	username, hashedPassword)
	// _, err = db.Exec(insertQuery)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("User created successfully!")
}

// func checkPasswordHash(hashedPassword string, providedPassword string) bool {
// 	generatedHash := generatePasswordHash(providedPassword)

// 	return generatedHash == hashedPassword
// }

// func generatePasswordHash(password string) string {
// 	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(hash)
// }
