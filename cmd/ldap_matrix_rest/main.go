package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/marcotuna/GoLDAPOpenVPN/conf"
	"github.com/marcotuna/GoLDAPOpenVPN/controllers"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// Config File Structure
type Config struct {
	LDAP ldap.Source
}

var (
	configurationFile = flag.String("config", "config.toml", "Configuration file location")
)

func main() {

	flag.Parse()

	// Load Configuration File
	configData, err := conf.LoadConfiguration(*configurationFile)
	if err != nil {
		log.Error(2, "%v", err.Error())
		os.Exit(1)
	}

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.TraceLevel)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	authMatrixCtrl, err := controllers.NewAuthMatrixRunner(configData)

	if err != nil {
		log.Error(2, "%v", err.Error())
	}

	r.POST("/_matrix-internal/identity/v1/check_credentials", authMatrixCtrl.AuthMatrixSynapse)

	srv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: r,
	}

	log.Infof("Webserver listening on %s:%d", "0.0.0.0", 8080)

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
