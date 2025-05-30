package v4jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

const jwtVersion = "1.2.3"

// VersionError is triggered in the validation method when the passed JWT string
// contains a version that doent match the version exposed above
type VersionError struct {
	Message string
}

func (e *VersionError) Error() string {
	return e.Message
}

// This is a private claims structure that includes the
// necessary JWT standard claims
type jwtClaims struct {
	UserID          string `json:"userId"`
	Barcode         string `json:"barcode"`
	IsUVA           bool   `json:"isUva"`
	HomeLibrary     string `json:"homeLibrary"`
	Profile         string `json:"profile"`
	CanPurchase     bool   `json:"canPurchase"`
	CanLEO          bool   `json:"canLEO"`
	CanLEOPlus      bool   `json:"canLEOPlus"`
	CanPlaceReserve bool   `json:"canPlaceReserve"`
	LEOLocation     string `json:"leoLocation"`
	IlliadCleared   string `json:"illiadCleared"`
	HasIlliad       bool   `json:"hasIlliad"`
	UseSIS          bool   `json:"useSIS"`
	Role            string `json:"role"`
	AuthMethod      string `json:"authMethod"`
	Version         string `json:"version"`
	jwt.StandardClaims
}

// Mint will create a new JWT for Virgo4 using the claims and signing key provided
func Mint(v4Claims V4Claims, duration time.Duration, jwtKey string) (string, error) {
	if v4Claims.Role == Guest {
		if v4Claims.UserID == "" {
			v4Claims.UserID = "anonymous"
			v4Claims.AuthMethod = NoAuth
		}
	} else {
		if v4Claims.UserID == "" {
			return "", errors.New("UserID is required for non-Guest roles")
		}
	}

	expirationTime := time.Now().Add(duration)
	claims := jwtClaims{
		UserID:          v4Claims.UserID,
		Barcode:         v4Claims.Barcode,
		IsUVA:           v4Claims.IsUVA,
		HomeLibrary:     v4Claims.HomeLibrary,
		Profile:         v4Claims.Profile,
		CanPurchase:     v4Claims.CanPurchase,
		CanLEO:          v4Claims.CanLEO,
		CanLEOPlus:      v4Claims.CanLEOPlus,
		CanPlaceReserve: v4Claims.CanPlaceReserve,
		LEOLocation:     v4Claims.LEOLocation,
		IlliadCleared:   v4Claims.IlliadCleared,
		HasIlliad:       v4Claims.HasIlliad,
		UseSIS:          v4Claims.UseSIS,
		Role:            v4Claims.Role.String(),
		AuthMethod:      v4Claims.AuthMethod.String(),
		Version:         jwtVersion,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			// IssuedAt:  time.Now().Unix(),
			Issuer: "v4",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedStr, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		return "", err
	}

	return signedStr, nil
}

// Refresh will verify the signature of a token, refresh its expiration time and re-sign
func Refresh(signedStr string, duration time.Duration, jwtKey string) (string, error) {
	jwtClaims := &jwtClaims{}
	_, jwtErr := jwt.ParseWithClaims(signedStr, jwtClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	// It is OK for a token to be expired when renewing
	if jwtErr != nil {
		valErr, _ := jwtErr.(*jwt.ValidationError)
		if valErr.Errors != jwt.ValidationErrorExpired {
			return "", jwtErr
		}
	}

	expirationTime := time.Now().Add(duration)
	jwtClaims.StandardClaims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
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

	if jwtClaims.Version != jwtVersion {
		ve := VersionError{Message: fmt.Sprintf("bad jwt version %s for %s", jwtClaims.Version, jwtClaims.UserID)}
		return nil, &ve
	}

	out := V4Claims{
		UserID:          jwtClaims.UserID,
		Barcode:         jwtClaims.Barcode,
		IsUVA:           jwtClaims.IsUVA,
		HomeLibrary:     jwtClaims.HomeLibrary,
		Profile:         jwtClaims.Profile,
		CanPurchase:     jwtClaims.CanPurchase,
		CanLEO:          jwtClaims.CanLEO,
		CanLEOPlus:      jwtClaims.CanLEOPlus,
		CanPlaceReserve: jwtClaims.CanPlaceReserve,
		LEOLocation:     jwtClaims.LEOLocation,
		IlliadCleared:   jwtClaims.IlliadCleared,
		HasIlliad:       jwtClaims.HasIlliad,
		UseSIS:          jwtClaims.UseSIS,
		Role:            RoleFromString(jwtClaims.Role),
		AuthMethod:      AuthFromString(jwtClaims.AuthMethod)}
	return &out, nil
}
