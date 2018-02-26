package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func genAuthHeader(username, password string) string {
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	return fmt.Sprintf("Basic %s", encodedPass)
}

func TestBasicAuth(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	session := createStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}

	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}
	wrongPassword := map[string]string{"Authorization": genAuthHeader("user", "wrong")}
	wrongFormat := map[string]string{"Authorization": genAuthHeader("user", "password:more")}
	malformed := map[string]string{"Authorization": "not base64"}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: http.StatusOK},
		{Method: "GET", Path: "/", Code: http.StatusUnauthorized, BodyMatch: `Authorization field missing`},
		{Method: "GET", Path: "/", Headers: validPassword, Code: http.StatusOK},
		{Method: "GET", Path: "/", Headers: wrongPassword, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: wrongFormat, Code: http.StatusBadRequest, BodyMatch: `Attempted access with malformed header, not in basic auth format`},
		{Method: "GET", Path: "/", Headers: malformed, Code: http.StatusBadRequest, BodyMatch: `Attempted access with malformed header, auth data not encoded correctly`},
	}...)
}
