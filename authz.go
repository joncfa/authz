// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package authz

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func NewAuthorizer(e *casbin.Enforcer, getSubjects func(r *http.Request) []string) gin.HandlerFunc {
	a := &authorizer{enforcer: e, getSubjects: getSubjects}

	return func(c *gin.Context) {
		if !a.checkPermission(c.Request) {
			c.AbortWithStatus(http.StatusForbidden)
		}
	}
}

type authorizer struct {
	enforcer    *casbin.Enforcer
	getSubjects func(r *http.Request) []string
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func GetSubjectBasicAuth(r *http.Request) []string {
	username, _, _ := r.BasicAuth()
	return []string{username}
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *authorizer) checkPermission(r *http.Request) bool {
	for _, sub := range a.getSubjects(r) {
		user := sub
		method := r.Method
		path := r.URL.Path

		allowed, err := a.enforcer.Enforce(user, path, method)
		if err != nil {
			panic(err)
		}
		if allowed {
			return true
		}
	}

	return false
}
