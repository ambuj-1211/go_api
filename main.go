package main

import (
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

func main() {
	http.HandleFunc("/", start)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/home", Home)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)

	log.Fatal(http.ListenAndServe(":8080", nil))
	database()

}
