package jwtAuth

import (
	"net/http"
	"strings"
	"log"
	jwt "github.com/dgrijalva/jwt-go"
)

var JwtAuthExcludedList []string

var ProcessErr func(msg string, w http.ResponseWriter)

var TOKEN_SECRET string

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestPath := r.URL.Path //current request path

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range JwtAuthExcludedList {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		processToken := func(t *jwt.Token) {
			if t.Valid {
				//Everything went well, proceed with the request
				next.ServeHTTP(w, r)
			} else { //Token is invalid, maybe not signed on this server
				ProcessErr("Token is not valid.", w)
			}
		}
		ProcessAuthorizationHeader(w, r, processToken, ProcessErr)
	});
}

func ProcessAuthorizationHeader(w http.ResponseWriter, r *http.Request, processToken func(t *jwt.Token), processError func(msg string, w http.ResponseWriter)) {
	tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

	if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
		processError("Missing auth token", w)
		return
	}

	splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
	if len(splitted) != 2 {
		processError("Invalid/Malformed auth token", w)
		return
	}

	tokenPart := splitted[1] //Grab the token part, what we are truly interested in

	token, err := jwt.ParseWithClaims(tokenPart, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(TOKEN_SECRET), nil
	})

	if err != nil { //Malformed token, returns with http code 403 as usual
		log.Println(err)
		processError("Malformed authentication token or token timeout", w)
		return
	}

	processToken(token)
}
