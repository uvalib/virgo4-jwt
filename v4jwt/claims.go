package v4jwt

// Private values for enum types
var authValues = [...]string{"none", "pin", "netbadge"}
var roleValues = [...]string{"guest", "user", "admin", "pdaadmin"}

// RoleEnum is the enumerated type for V4 user role
type RoleEnum int

const (
	// Guest is a non-authenticated user
	Guest RoleEnum = iota
	// User is a standard signed in user
	User
	// Admin is a signed in user with admin privileges
	Admin
	// PDAAdmin is a signed in user with PDA admin privileges
	PDAAdmin
)

// RoleFromString converts string roles to Enum
func RoleFromString(str string) RoleEnum {
	out := Guest
	for idx, val := range roleValues {
		if val == str {
			out = RoleEnum(idx)
			break
		}
	}
	return out
}

func (r RoleEnum) String() string {
	if r < 0 || r > 3 {
		return "guest"
	}
	return roleValues[r]
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

// AuthFromString converts string auth to AuthEnum
func AuthFromString(str string) AuthEnum {
	out := NoAuth
	for idx, val := range authValues {
		if val == str {
			out = AuthEnum(idx)
			break
		}
	}
	return out
}

func (r AuthEnum) String() string {
	if r < 0 || r > 2 {
		return "none"
	}
	return authValues[r]
}

// V4Claims encapsulates all of the information about Virgo4 user
type V4Claims struct {
	UserID          string   `json:"userId"` // v4 userID or anonymous
	IsUVA           bool     `json:"isUva"`
	HomeLibrary     string   `json:"homeLibrary"`
	Profile         string   `json:"profile"`
	CanPurchase     bool     `json:"canPurchase"`
	CanLEO          bool     `json:"canLEO"`
	CanLEOPlus      bool     `json:"canLEOPlus"`
	CanPlaceReserve bool     `json:"canPlaceReserve"`
	UseSIS          bool     `json:"useSIS"`
	Role            RoleEnum `json:"role"`       // guest, user, admin
	AuthMethod      AuthEnum `json:"authMethod"` // none, pin, netbadge
}
