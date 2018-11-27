package models

import "regexp"

// User ...
type User struct {
	User *UserDetails `json:"user"`
}

// UserDetails ...
type UserDetails struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

//Auth ...
type Auth struct {
	Success bool         `json:"success"`
	Mxid    string       `json:"mxid"`
	Profile *UserProfile `json:"profile"`
}

// UserProfile ...
type UserProfile struct {
	DisplayName string           `json:"display_name"`
	ThreePids   []*UserThreePids `json:"three_pids"`
}

// UserThreePids ...
type UserThreePids struct {
	Medium  string `json:"medium"`
	Address string `json:"address"`
}

// ExtractUsernameFromMatrixID gets username from the matrix id
func ExtractUsernameFromMatrixID(userMatrixID string) string {
	re := regexp.MustCompile(`@(.*):\w+`)
	match := re.FindStringSubmatch(userMatrixID)
	return match[1]
}
