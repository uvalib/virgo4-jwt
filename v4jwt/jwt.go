package v4jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// This is a private claims structure that includes the
// necessary JWT standard claims
type jwtClaims struct {
	V4Claims
	jwt.StandardClaims
}

// Mint will create a new JWT for Virgo4 using the claims and signing key provided
func Mint(v4Claims V4Claims, duration time.Duration, jwtKey string) (string, error) {
	if v4Claims.Role == Guest {
		v4Claims.UserID = "anonymous"
		v4Claims.AuthMethod = NoAuth
	} else {
		if v4Claims.UserID == "" {
			return "", errors.New("UserID is required for non-Guest roles")
		}
	}

	expirationTime := time.Now().Add(duration)
	claims := jwtClaims{
		V4Claims: v4Claims,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "v4",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		return "", err
	}

	return signedStr, nil
}

// Validate will verify the signature of a token and return the claims it contains
func Validate(signedStr string, jwtKey string) (*V4Claims, error) {
	jwtClaims := &jwtClaims{}
	_, jwtErr := jwt.ParseWithClaims(signedStr, jwtClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	if jwtErr != nil {
		return nil, jwtErr
	}
	out := V4Claims{UserID: jwtClaims.UserID,
		IsUVA:            jwtClaims.IsUVA,
		CanPurchase:      jwtClaims.CanPurchase,
		CanLEO:           jwtClaims.CanLEO,
		CanLEOPlus:       jwtClaims.CanLEOPlus,
		CanPlaceReserve:  jwtClaims.CanPlaceReserve,
		CanBrowseReserve: jwtClaims.CanBrowseReserve,
		UseSIS:           jwtClaims.UseSIS,
		Role:             jwtClaims.Role,
		AuthMethod:       jwtClaims.AuthMethod}
	return &out, nil
}