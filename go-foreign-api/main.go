package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const entriesFolder = "entries"

func getAuthServerUrl() string {
	const authServerUrlEnv = "AUTH_SERVER_URL"
	serverUrl := os.Getenv(authServerUrlEnv)
	if len(serverUrl) > 0 {
		return serverUrl
	}

	return "127.0.0.1:9090"
}

var authServerUrl = "http://" + getAuthServerUrl()

var authVerifyTokenUrl = authServerUrl + "/verify"

// it's meant to be a foreign service(aka third party), so it's not put into shared module
type PersonEntry struct {
	Name string `form:"name" json:"name"`
	Age  int    `form:"age" json:"age"`
}

func extractTokenFromAuthHeader(auth string) (string, bool) {
	if !strings.Contains(auth, "Bearer ") {
		return "", false
	}
	token := auth[len("Bearer "):]

	return token, true
}
func authorize(ctx *gin.Context) (int, bool) {
	authH := ctx.GetHeader("Authorization")

	var client http.Client

	req, _ := http.NewRequest("POST", authVerifyTokenUrl, nil)
	req.Header.Add("Authorization", authH)

	resp, err := client.Do(req)

	if err != nil {
		//ctx.String(400, "Failed to do verification")
		return 400, false
	}

	if resp.StatusCode >= 300 {
		//ctx.String(resp.StatusCode, "Verification failed, not authorized")
		return resp.StatusCode, false
	}

	return 200, true
}
func handleAddPerson(ctx *gin.Context) {
	authRespCode, authSucceed := authorize(ctx)

	if !authSucceed {
		ctx.String(authRespCode, "Verification failed, not authorized")
		return
	}

	var p PersonEntry
	if ctx.ShouldBind(&p) == nil {
		fmt.Printf("Got person name: %s\n", p.Name)

		pJson, _ := json.Marshal(&p)

		fmt.Printf("Resulting json string: %s", pJson)

		id := uuid.New()
		err := os.WriteFile(
			entriesFolder+"/"+fmt.Sprintf("%s.json", id.String()),
			pJson,
			os.ModeAppend,
		)
		if err != nil {
			ctx.String(500, "Can't handle file write")
			return
		}

		ctx.String(201, id.String())

		//201
	} else {
		ctx.String(400, "Invalid request")
	}
}
func handleEntries(ctx *gin.Context) {
	authRespCode, authSucceed := authorize(ctx)

	if !authSucceed {
		ctx.String(authRespCode, "Verification failed, not authorized")
		return
	}

	dirEntries, _ := os.ReadDir(entriesFolder)
	res := ""
	for _, e := range dirEntries {
		res += e.Name() + "\n"
	}
	ctx.String(200, res)
}

func main() {
	g := gin.Default()
	g.POST("/addperson", handleAddPerson)
	g.GET("/entries", handleEntries)
	g.Run(":9092")
}
