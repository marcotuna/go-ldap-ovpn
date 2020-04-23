package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/marcotuna/GoLDAPOpenVPN/config"
	"github.com/marcotuna/GoLDAPOpenVPN/controllers"
	"github.com/marcotuna/GoLDAPOpenVPN/logger"
	log "github.com/sirupsen/logrus"
)

var (
	configurationFile = flag.String("config", "config.toml", "Configuration file location")
)

func main() {

	flag.Parse()

	// Load Configuration File
	configData, err := config.LoadConfiguration(*configurationFile)
	if err != nil {
		log.Errorf("%v", err.Error())
		os.Exit(1)
	}

	initLogger, err := logger.NewRunner(configData)

	if err != nil {
		log.Error(2, "%v", err.Error())
	}

	initLogger.Initialize()

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
