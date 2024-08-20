package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	uniuri "github.com/dchest/uniuri"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	goapp "github.com/sam-haff/go-api-services/go-api-shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const tokenLen = 10

var mongoClient *mongo.Client

const mongoDBName = "go-api-app"
const mongoDBTokensCollection = "tokens"

type OauthClient struct {
	Client_id     string
	Client_secret string
	Redirect_uri  string
}

func printEnvVarNotFound(n string) {
	fmt.Printf("Env var %s not found \n", n)
}

func getClientServerUrl() string {
	const clientServerUrlEnv = "CLIENT_SERVER_URL"
	serverUrl := os.Getenv(clientServerUrlEnv)
	if len(serverUrl) > 0 {
		return serverUrl
	}

	printEnvVarNotFound(clientServerUrlEnv)
	return "127.0.0.1:9091"
}

var clientServerUrl = "http://" + getClientServerUrl()

var clients = []OauthClient{
	{
		Client_id:     "oauth-client-1",
		Client_secret: "oauth-client-secret-1",
		Redirect_uri:  clientServerUrl + "/callback",
	},
}

type CodeRecord struct {
	ClientId string
}

var codes map[string]CodeRecord = make(map[string]CodeRecord)

func retrieveClient(id string) *OauthClient {
	for _, client := range clients {
		if client.Client_id == id {
			return &client
		}
	}
	return nil
}

func handleToken(ctx *gin.Context) {
	fmt.Printf("Handle Token \n")

	authH := ctx.GetHeader("Authorization")

	if !strings.Contains(authH, "Basic ") {
		fmt.Printf("No creds found \n")

		ctx.String(401, "Invalid header")
		return
	}

	credsBytes, _ := base64.StdEncoding.DecodeString(authH[len("Basic "):])

	fmt.Printf("Got creads %s \n", credsBytes)

	creds := string(credsBytes)
	credEls := strings.Split(creds, ":")
	clientID := credEls[0]
	clientSecret := credEls[1]
	client := retrieveClient(clientID)
	if client == nil {
		fmt.Printf("Uknown client \n")
		ctx.String(401, "Uknown client")
		return
	}
	if client.Client_secret != clientSecret {
		fmt.Printf("Invalid creds \n")
		ctx.String(401, "Invalid client creds")
		return
	}
	var reqBody goapp.TokenRequestBody
	if ctx.ShouldBind(&reqBody) == nil {
		fmt.Printf("Got auth code: %s \n", reqBody.Code)
		fmt.Printf("%s \n", reqBody.GrantType)

		if reqBody.GrantType != "authorization_code" {
			fmt.Printf("Unsupported grant \n")
			ctx.String(401, "Unsupported grant type")
			return
		}

		cd, ok := codes[reqBody.Code]
		if !ok {

			fmt.Printf("Unsupported code %s\n", cd.ClientId)
			ctx.String(401, "Unrecognized code")

			return
		}

		token := uniuri.NewLen(tokenLen)
		fmt.Printf("Generated token %s", token)

		tokenEntry := goapp.TokenEntryDb{
			token,
			"",
			credEls[0],
		}

		fmt.Printf("Inserting token...")
		_, err := mongoClient.Database(mongoDBName).Collection(mongoDBTokensCollection).InsertOne(context.TODO(), tokenEntry)
		if err != nil {
			fmt.Printf("Failed to write token to db, with %s\n", err.Error())
			ctx.String(401, "Failed to write token to database, with %s", err.Error())
			return
		}

		resp := goapp.TokenResponse{"Bearer",
			token,
			""}

		fmt.Printf("Sending token...")
		ctx.AsciiJSON(200, resp)

		return
	}
	ctx.String(401, "Invalid body format")
}
func checkMapHandler(ctx *gin.Context) {
	fmt.Printf("resulting map %v", codes)

}
func authHandler(ctx *gin.Context) {
	fmt.Printf("Auth begins... \n")

	q := goapp.AuthQuery{}
	if ctx.ShouldBindQuery(&q) == nil {
		client := retrieveClient(q.Client_id)

		if client == nil {
			ctx.String(401, "Client does not exist")
			return
		}
		if client.Redirect_uri != q.Redirect_uri {
			fmt.Printf("Uris don't match, expected: %s, got:%s \n", client.Redirect_uri, q.Redirect_uri)
			ctx.String(401, "Uris dont match")
		}
		if q.Response_type != "code" {
			ctx.String(401, "Unsupported resp type")
		}
		code := uniuri.NewLen(8)
		codes[code] = CodeRecord{q.Client_id}

		fmt.Printf("generated code %s \n")
		fmt.Printf("resulting map %v", codes)

		redirUrl, _ := url.Parse("/approve")
		redirQ := redirUrl.Query()
		redirQ.Add("code", code)
		redirQ.Add("client_id", q.Client_id)
		redirQ.Add("redirect_uri", q.Redirect_uri)
		redirQ.Add("response_type", q.Response_type)
		redirQ.Add("state", q.State)
		redirUrl.RawQuery = redirQ.Encode()

		ctx.Redirect(http.StatusFound, redirUrl.String())

		return
	}

	ctx.String(400, "Fail")
}

func approveHandler(ctx *gin.Context) {
	var q goapp.ApproveRedirQuery = goapp.ApproveRedirQuery{}

	if ctx.ShouldBindQuery(&q) == nil {
		callbackUrl, _ := url.Parse(q.Redirect_uri)
		callbackQ := callbackUrl.Query()
		callbackQ.Add("code", q.Code)
		callbackQ.Add("state", q.State)
		callbackUrl.RawQuery = callbackQ.Encode()

		ApprovePage("gav", callbackUrl.String()).Render(ctx.Request.Context(), ctx.Writer)

		return
	}

	ctx.String(400, "Fail")
}

func extractTokenFromAuthHeader(auth string) (string, bool) {
	if !strings.Contains(auth, "Bearer ") {
		return "", false
	}
	token := auth[len("Bearer "):]
	if len(token) != tokenLen {
		return "", false
	}
	return token, true
}

func verifyTokenHandler(ctx *gin.Context) {
	token, ok := extractTokenFromAuthHeader(ctx.GetHeader("Authorization"))

	if !ok {
		ctx.String(401, "Invalid token format")
		return
	}

	filter := bson.D{{"access_token", token}}
	fmt.Printf("Got auth header: %s", ctx.GetHeader("Authorization"))
	fmt.Printf("Got token %s \n", token)

	foundToken := goapp.TokenEntryDb{}
	err := mongoClient.Database(mongoDBName).Collection(mongoDBTokensCollection).FindOne(context.TODO(), filter).Decode(&foundToken)
	if err != nil {
		ctx.String(404, "Unauthorized")
		return
	}

	ctx.String(201, "Authorized")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Critical. Failed to load env var.")
		return
	}

	mongoConnectionUri := os.Getenv("MONGODB_CONNECTION_URL")
	mongoClient, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoConnectionUri))
	if err != nil {
		fmt.Printf("conn uri: %s", mongoConnectionUri)
		fmt.Printf("Failed to conenct to mongodb, err: %s\n", err.Error())
		return
	}

	f, err := os.OpenFile("testlogfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	wrt := io.MultiWriter(os.Stdout, f)
	log.SetOutput(wrt)
	log.SetOutput(f)

	g := gin.Default()
	g.GET("/auth", authHandler)
	g.GET("/approve", approveHandler)
	g.POST("/token", handleToken)
	g.POST("/verify", verifyTokenHandler)
	g.GET("/map", checkMapHandler)
	g.Run(":9090")
}
