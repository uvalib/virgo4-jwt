# Virgo4 JWT

This is the JWT library for Virgo4 services written in Go. It can mint new tokens 
and validate existing tokens. The example directory includes sample usage of 
this library.

To run the examples, execute ```go run example/main.go```

# API

This library supports a set of claims specific to Virgo4. They are found in v4jwt.V4Claims:

* UserID 
* IsUVA  
* CanPurchase
* CanLEO
* CanLEOPlus
* CanPlaceReserve 
* UseSIS 
* Role (required)
* AuthMethod

Role is an enumerated type with values: Guest, User and Admin. All but Guest require a UserID.
AuthMethod is an enumarated type with values: NoAuth, PIN and Netbadge. When Role is guest this defaults to NoAuth.

There are two API calls

* Mint(V4Claims, Duration, SigningKey) : this takes the claims, duration and key and generates a signed JWT string.
* Validate(JWTString, SigningKey) : this validates the key for signature and expiration and returns the claims.


### System Requirements
* GO version 1.14 or greater (mod required)