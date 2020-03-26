package v4jwt

// RoleEnum is the enumerated type for V4 user role
type RoleEnum int

const (
	// Guest is a non-authenticated user
	Guest RoleEnum = iota
	// User is a standard signed in user
	User
	// Admin is a signed in user with admin privileges
	Admin
)

func (r RoleEnum) String() string {
	if r < 0 || r > 2 {
		return "guest"
	}
	return [...]string{"guest", "user", "admin"}[r]
}

// AuthEnum is the enumerated type for V4 user authentication methods
type AuthEnum int

const (
	// NoAuth indicates there as no authentication
	NoAuth AuthEnum = iota
	// PIN indicates authentication using a Sirsi PIN
	PIN
	// Netbadge indicates authentication using Netbadge
	Netbadge
)

func (r AuthEnum) String() string {
	if r < 0 || r > 2 {
		return "none"
	}
	return [...]string{"none", "pin", "netbadge"}[r]
}

// V4Claims encapsulates all of the information about Virgo4 user
type V4Claims struct {
	UserID           string   `json:"userId"` // v4 userID or anonymous
	IsUVA            bool     `json:"isUva"`
	CanPurchase      bool     `json:"canPurchase"`
	CanLEO           bool     `json:"canLEO"`
	CanLEOPlus       bool     `json:"canLEOPlus"`
	CanPlaceReserve  bool     `json:"canPlaceReserve"`
	CanBrowseReserve bool     `json:"canBrowseReserve"`
	UseSIS           bool     `json:"useSIS"`
	Role             RoleEnum `json:"role"`       // guest, user, admin
	AuthMethod       AuthEnum `json:"authMethod"` // none, pin, netbadge
}
