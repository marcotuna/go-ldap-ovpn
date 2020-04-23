package controllers

import "github.com/marcotuna/GoLDAPOpenVPN/config"

// Runner ...
type Runner struct {
	Configuration config.Config
}

// NewRunner ...
func NewRunner(conf *config.Config) (*Runner, error) {

	runnerStruct := &Runner{
		Configuration: *conf,
	}

	return runnerStruct, nil
}
