package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/marcotuna/GoLDAPOpenVPN/conf"
	"github.com/marcotuna/GoLDAPOpenVPN/controllers"
	log "github.com/sirupsen/logrus"
)

var (
	configurationFile = flag.String("config", "config.toml", "Configuration file location")
)

func main() {

	flag.Parse()

	// Load Configuration File
	configData, err := conf.LoadConfiguration(*configurationFile)
	if err != nil {
		log.Errorf("%v", err.Error())
		os.Exit(1)
	}

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	switch strings.ToLower(configData.Log.Mode) {
	case "console":
		log.SetOutput(os.Stdout)
		break
	case "file":
		logger := log.New()
		log.SetOutput(logger.Writer())

		f, err := os.OpenFile(configData.Log.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
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
	logLevel, err := log.ParseLevel(configData.Log.Level)
	if err != nil {
		log.Errorf("%v", err.Error())
	}
	log.SetLevel(logLevel)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	runnerCtrl, err := controllers.NewRunner(configData)

	if err != nil {
		log.Error(2, "%v", err.Error())
	}

	r.POST("/_matrix-internal/identity/v1/check_credentials", runnerCtrl.AuthMatrixSynapse)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", configData.Server.IP, configData.Server.Port),
		Handler: r,
	}

	log.Infof("Webserver listening on %s:%d", configData.Server.IP, configData.Server.Port)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Listen: %s", err)
			return
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Trace("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("Server Shutdown: %s", err)
	}

	log.Trace("Server exiting")

}
