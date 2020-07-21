package main

import (
	"log"
	"time"

	"github.com/uvalib/virgo4-jwt/v4jwt"
)

/**
 * MAIN
 */
func main() {
	signingKey := "v4_test_key"

	log.Printf("Test generation of anonymous JWT")
	claims := v4jwt.V4Claims{Role: v4jwt.Guest}
	jwtStr, err := v4jwt.Mint(claims, 5*time.Minute, signingKey)
	if err != nil {
		log.Printf("ERROR: Unable to mint anonymous JWT: %s", err.Error())

	} else {
		log.Printf("SUCCESS: New JWT: %s", jwtStr)
	}

	log.Printf("Test invalid mint (no UserID)...")
	claims = v4jwt.V4Claims{Role: v4jwt.Admin}
	jwtStr, err = v4jwt.Mint(claims, 5*time.Minute, signingKey)
	if err != nil {
		log.Printf("SUCCESS: mint JWT without userID failed %s", err.Error())

	} else {
		log.Printf("ERROR: Generated non-Guest JWT without UserID: %s", jwtStr)
	}

	log.Printf("Test generation of Admin Purchaser JWT")
	claims = v4jwt.V4Claims{UserID: "admin1", Role: v4jwt.Admin, CanPurchase: true, AuthMethod: v4jwt.Netbadge}
	jwtStr, err = v4jwt.Mint(claims, 5*time.Minute, signingKey)
	if err != nil {
		log.Printf("ERROR: Unable to mint admin JWT: %s", err.Error())

	} else {
		log.Printf("SUCCESS: New admin JWT: %s", jwtStr)
	}

	log.Printf("Test validation with bad key")
	_, vErr := v4jwt.Validate(jwtStr, "bad")
	if vErr != nil {
		log.Printf("SUCCESS: unable to validate JWT: %s", vErr.Error())
	} else {
		log.Printf("ERROR: Validated WITH BAD KEY")
	}

	log.Printf("Generate short lived JWT with renew")
	claims = v4jwt.V4Claims{Role: v4jwt.Guest}
	jwtStr, err = v4jwt.Mint(claims, 3*time.Second, signingKey)
	if err != nil {
		log.Printf("ERROR: Unable to mint anonymous JWT: %s", err.Error())
	} else {
		log.Printf("SUCCESS, delay for 2 seconds, then renew...")
		time.Sleep(2 * time.Second)
		refreshed, err := v4jwt.Refresh(jwtStr, 3*time.Second, signingKey)
		if err != nil {
			log.Printf("ERROR: unable to refresh JWT")
		} else {
			log.Printf("SUCCESS, delay for 2 seconds and make sure still valid")
			time.Sleep(2 * time.Second)
			_, vErr := v4jwt.Validate(refreshed, signingKey)
			if vErr != nil {
				log.Printf("ERROR: unable to validate refreshed JWT")
			} else {
				log.Printf("SUCCESS, delay for 2 seconds and make sure it is not valid")
				time.Sleep(2 * time.Second)
				_, vErr := v4jwt.Validate(jwtStr, signingKey)
				if vErr != nil {
					log.Printf("SUCCESS: JWT did not validate: %s", vErr.Error())
				} else {
					log.Printf("ERROR: JWT not expired")
				}
			}
		}
	}
}
