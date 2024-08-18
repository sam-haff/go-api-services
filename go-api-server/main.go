package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

var currentToken = "NONE"

const authUrl = "http://localhost:9090/auth"
const tokenUrl = "http://localhost:9090/token"

const clientId = "oauth-client-1"
const clientSecret = "oauth-client-secret-1"
const redirectUri = "http://localhost:9091/callback"
const state = "empty"

func encodeClientCreds(id string, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
}

type CallbackQuery struct {
	Code  string `form:"code" json:"code"`
	State string `form:"state" json:"state"`
}

func handleIndex(ctx *gin.Context) {
	authUrl, _ := url.Parse(authUrl)
	authUrlQ := authUrl.Query()
	authUrlQ.Add("client_id", clientId)
	authUrlQ.Add("response_type", "code")
	authUrlQ.Add("redirect_uri", redirectUri)
	authUrlQ.Add("state", state)
	authUrl.RawQuery = authUrlQ.Encode()
	IndexPage(currentToken, authUrl.String()).Render(ctx.Request.Context(), ctx.Writer)
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

		fmt.Printf("Token Form Data %s \n", bodyEncoded.Encode())

		client := http.Client{}
		req, _ := http.NewRequest("POST", tokenUrl, bytes.NewBuffer([]byte(bodyEncoded.Encode())))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Authorization", "Basic "+encodeClientCreds(clientId, clientSecret))

		resp, err := client.Do(req)

		if err != nil {
			fmt.Printf("Failed to send code back to the server\n")
		}

		b, err := ioutil.ReadAll(resp.Body)

		fmt.Printf("%s \n", b)
	}
}

func main() {
	g := gin.Default()
	g.GET("/", handleIndex)
	g.GET("/callback", handleCallback)
	g.Run(":9091")
}
