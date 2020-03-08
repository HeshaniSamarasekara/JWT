package dto

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

// User - User struct
type User struct {
	Username string
	Password string
}

// Claims - JWT token claim
type Claims struct {
	Username   string `json:"username"`
	Authorized bool   `json:"authorized"`
	jwt.StandardClaims
}

// TokenStruct - Return token
type TokenStruct struct {
	Name    string    `json:"name"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}
