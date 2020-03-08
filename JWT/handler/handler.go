package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"JWT/dto"

	"github.com/dgrijalva/jwt-go"
)

// LoginUser - User login
func LoginUser(s Service) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		var userRequest dto.User
		_ = json.NewDecoder(req.Body).Decode(&userRequest)
		returnToken := dto.TokenStruct{}

		tokenString, expirationTime, err := s.LoginUser(userRequest)

		if (err != dto.ServiceError{}) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(err)
			return
		}
		returnToken.Name = "token"
		returnToken.Token = tokenString
		returnToken.Expires = expirationTime
		json.NewEncoder(w).Encode(returnToken)
	}
}

// RefreshToken -  Refresh JWT token
func RefreshToken(s Service) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		hdrtocken := req.Header["Token"]
		if hdrtocken == nil || len(hdrtocken) < 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenStr := hdrtocken[0]
		claims := &dto.Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return getSignKey(), nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return

		}

		if time.Now().Sub(time.Unix(claims.ExpiresAt, 0)) > 30*time.Second {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}

		expirationTime := time.Now().Add(5 * time.Minute)
		claims.ExpiresAt = expirationTime.Unix()

		returnToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := returnToken.SignedString(getSignKey())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tkn := dto.TokenStruct{}
		tkn.Name = "token"
		tkn.Token = tokenString
		tkn.Expires = expirationTime

		json.NewEncoder(w).Encode(tkn)
	}
}
