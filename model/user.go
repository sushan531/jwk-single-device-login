package model

// User represents a user in the system
type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
}

// ToMap converts a User to a map for JWT claims
func (u *User) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"id":       u.Id,
		"username": u.Username,
	}
}

// FromMap creates a User from a map (JWT claims)
func UserFromMap(data map[string]interface{}) *User {
	id, _ := data["id"].(float64)
	username, _ := data["username"].(string)
	
	return &User{
		Id:       int(id),
		Username: username,
	}
}
