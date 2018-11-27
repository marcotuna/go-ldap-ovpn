package controllers

import (
	"encoding/json"
	"io/ioutil"

	"github.com/gin-gonic/gin"
	"github.com/marcotuna/GoLDAPOpenVPN/models"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// AuthMatrixSynapse ...
func (ctrl Runner) AuthMatrixSynapse(c *gin.Context) {
	// Receive POST data in RAW
	reqBody := c.Request.Body
	rawContent, _ := ioutil.ReadAll(reqBody)

	// Initialize User Structure
	rcvUser := models.User{}

	// Parse RAW Data to User Struct
	if err := json.Unmarshal(rawContent, &rcvUser); err != nil {
		log.Error(2, err.Error())
		return
	}

	// Extract Username From Matrix User ID
	userUsername := models.ExtractUsernameFromMatrixID(rcvUser.User.ID)

	ldapConn := ldap.Initialize(ctrl.Configuration.LDAP)
	commonName, username, fn, sn, mail, isAdmin, succeed := ldapConn.SearchEntry(userUsername, rcvUser.User.Password, false)

	log.Tracef("Fetched from LDAP: '%v', '%v', '%v', '%v', '%v', '%v', '%v'", commonName, username, fn, sn, mail, isAdmin, succeed)

	authReq := models.Auth{
		Success: false,
		Mxid:    "",
	}

	if succeed {
		authReq = models.Auth{
			Success: true,
			Mxid:    rcvUser.User.ID,
			Profile: &models.UserProfile{
				DisplayName: commonName,
				ThreePids: []*models.UserThreePids{
					&models.UserThreePids{Medium: "uid", Address: commonName},
					&models.UserThreePids{Medium: "mail", Address: mail},
					&models.UserThreePids{Medium: "name", Address: fn},
				},
			},
		}
	}

	// Send Response
	c.JSON(200, gin.H{"auth": authReq})
}
