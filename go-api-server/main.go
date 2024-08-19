package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	goapp "github.com/sam-haff/go-api-services/go-api-shared"
)

var currentToken = "NONE"

const authUrl = "http://localhost:9090/auth"
const tokenUrl = "http://localhost:9090/token"
const verifyUrl = "http://localhost:9090/verify"

const clientId = "oauth-client-1"
const clientSecret = "oauth-client-secret-1"
const redirectUri = "http://localhost:9091/callback"

var state string = "0"

func encodeClientCreds(id string, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
}

type CallbackQuery struct {
	Code  string `form:"code" json:"code"`
	State string `form:"state" json:"state"`
}

func getState() string {
	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)
}

func handleIndex(ctx *gin.Context) {
	state = getState()

	authUrl, _ := url.Parse(authUrl)
	authUrlQ := authUrl.Query()
	authUrlQ.Add("client_id", clientId)
	authUrlQ.Add("response_type", "code")
	authUrlQ.Add("redirect_uri", redirectUri)
	authUrlQ.Add("state", fmt.Sprintf("%v", state))
	authUrl.RawQuery = authUrlQ.Encode()
	IndexPage(currentToken, authUrl.String(), "/tryToken").Render(ctx.Request.Context(), ctx.Writer)
}
func handleTryToken(ctx *gin.Context) {
	client := http.Client{}
	req, _ := http.NewRequest("POST", verifyUrl, nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+currentToken)

	resp, err := client.Do(req)

	if err != nil {
		ctx.String(401, "Failed to send code back to the server")
		return
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ctx.String(404, "Failed to read body")
	}
	ctx.String(resp.StatusCode, string(b))

}

type CallbackFormData struct {
	GrantType   string `url:"grant_type"`
	RedirectUri string `url:"redirect_uri"`
	Code        string `url:"code"`
	State       string `url:"state"`
}

func handleCallback(ctx *gin.Context) {
	var q CallbackQuery

	if ctx.ShouldBindQuery(&q) == nil {
		if len(q.Code) == 0 {
			ctx.String(401, "Failed")

			return
		}

		if q.State != state {
			ctx.String(401, "Failed: invalid state")

			return
		}

		body := CallbackFormData{
			"authorization_code",
			redirectUri,
			q.Code,
			state,
		}
		bodyEncoded, _ := query.Values(body)

		client := http.Client{}
		req, _ := http.NewRequest("POST", tokenUrl, bytes.NewBuffer([]byte(bodyEncoded.Encode())))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Authorization", "Basic "+encodeClientCreds(clientId, clientSecret))

		resp, err := client.Do(req)

		if err != nil {
			ctx.String(401, "Failed to send code back to the server")
			return
		}
		var tokenResp goapp.TokenResponse

		b, err := ioutil.ReadAll(resp.Body)
		err = json.Unmarshal(b, &tokenResp)
		if resp.StatusCode >= 300 {
			ctx.String(401, "Token request failed")
			return
		}
		if err != nil {
			ctx.String(401, "Failed to parse token response")
			return
		}

		currentToken = tokenResp.AccessToken

		ctx.Redirect(http.StatusMovedPermanently, "/")
	}
}

func main() {
	g := gin.Default()
	g.GET("/", handleIndex)
	g.GET("/callback", handleCallback)
	g.GET("/tryToken", handleTryToken)
	g.Run(":9091")
}
