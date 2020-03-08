package main

import (
	"log"
	"net/http"

	"JWT/handler"

	"github.com/gorilla/mux"
)

func main() {
	muxRouter := mux.NewRouter()
	userService := handler.NewService()
	// Login API route
	muxRouter.HandleFunc("/login", handler.LoginUser(userService)).Methods("POST")
	// Token refresh API route
	muxRouter.HandleFunc("/refresh", handler.RefreshToken(userService)).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", muxRouter))
}
