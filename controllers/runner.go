package controllers

import "github.com/marcotuna/GoLDAPOpenVPN/conf"

// Runner ...
type Runner struct {
	Configuration conf.Config
}

// NewRunner ...
func NewRunner(conf *conf.Config) (*Runner, error) {

	runnerStruct := &Runner{
		Configuration: *conf,
	}

	return runnerStruct, nil
}
