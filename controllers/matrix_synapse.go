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

	ldapConn := ldap.New(ldap.LDAP{
		Settings:   &ctrl.Configuration.LDAP,
		Connection: nil,
	})
	userEntry, err := ldapConn.SearchEntry(userUsername, rcvUser.User.Password, false)

	if err != nil {
		log.Error(2, err.Error())
		return
	}

	authReq := models.Auth{
		Success: false,
		Mxid:    "",
	}

	authReq = models.Auth{
		Success: true,
		Mxid:    rcvUser.User.ID,
		Profile: &models.UserProfile{
			DisplayName: userEntry.CommonName,
			ThreePids: []*models.UserThreePids{
				{Medium: "uid", Address: userEntry.CommonName},
				{Medium: "mail", Address: userEntry.Mail},
				{Medium: "name", Address: userEntry.FirstName},
			},
		},
	}

	// Send Response
	c.JSON(200, gin.H{"auth": authReq})
}
