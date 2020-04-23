package logger

import (
	"os"
	"strings"

	"github.com/marcotuna/GoLDAPOpenVPN/config"
	log "github.com/sirupsen/logrus"
)

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

// Initialize ...
func (ctrl Runner) Initialize() {
	switch strings.ToLower(ctrl.Configuration.Log.Mode) {
	case "console":
		log.SetOutput(os.Stdout)
		break
	case "file":
		logger := log.New()
		log.SetOutput(logger.Writer())

		f, err := os.OpenFile(ctrl.Configuration.Log.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
		if err != nil {
			log.Errorf("Failed to initialize log file %s", err)
			os.Exit(1)
		}

		logger.Out = f
		break
	default:
		log.SetOutput(os.Stdout)
	}

	// Only log the warning severity or above.
	logLevel, err := log.ParseLevel(ctrl.Configuration.Log.Level)
	if err != nil {
		log.Errorf("%v", err.Error())
	}
	log.SetLevel(logLevel)
}
