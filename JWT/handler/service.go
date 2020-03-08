package handler

import (
	"flag"
	"io/ioutil"
	"log"
	"time"

	"JWT/dto"

	"github.com/dgrijalva/jwt-go"
	"github.com/magiconair/properties"
)

// Service - Interface
type Service interface {
	LoginUser(dto.User) (string, time.Time, dto.ServiceError)
}

type service struct{}

// NewService - Get New service instance
func NewService() Service {
	return &service{}
}

var props *properties.Properties

func init() {
	configFile := flag.String("configFile", "application.properties", "Configuration File")
	flag.Parse()
	props = properties.MustLoadFile(*configFile, properties.UTF8)
}

// LoginUser - Generates a JWT token
func (s *service) LoginUser(user dto.User) (string, time.Time, dto.ServiceError) {
	currentUserName := props.MustGetString("test-username")
	currentPassword := props.MustGetString("test-password")
	expirationTime := time.Now().Add(5 * time.Minute)

	if user.Username != currentUserName || user.Password != currentPassword {
		return "", time.Now().Add(0 * time.Minute), dto.ServiceError{Code: "401", Message: "Unauthorized User"}
	}

	claims := &dto.Claims{
		Username:   user.Username,
		Authorized: true,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signKey := getSignKey()

	if signKey == nil {
		return "", expirationTime, dto.ServiceError{Code: "500", Message: "Sign key not found. "}
	}

	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", expirationTime, dto.ServiceError{Code: "500", Message: err.Error()}
	}
	return tokenString, expirationTime, dto.ServiceError{}
}

func getSignKey() []byte {
	signKey, err := ioutil.ReadFile(props.MustGetString("sign-key-path"))
	if err != nil {
		log.Printf("Error while reading key file. ")
		return nil
	}

	return signKey
}
