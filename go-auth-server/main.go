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
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client

type OauthClient struct {
	Client_id     string
	Client_secret string
	Redirect_uri  string
}

var clients = []OauthClient{
	{
		Client_id:     "oauth-client-1",
		Client_secret: "oauth-client-secret-1",
		Redirect_uri:  "http://localhost:9091/callback",
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
		ctx.String(401, "Uknown client")
		return
	}
	if client.Client_secret != clientSecret {
		ctx.String(401, "Invalid client creds")
		return
	}
	var reqBody TokenRequestBody
	if ctx.ShouldBind(&reqBody) == nil {
		fmt.Printf("Got auth code: %s \n", reqBody.Code)
		fmt.Printf("%s \n", reqBody.GrantType)

		if reqBody.GrantType != "authorization_code" {
			ctx.String(401, "Unsupported grant type")
			return
		}

		_, ok := codes[reqBody.Code]
		if !ok {
			ctx.String(401, "Unrecognized code")
		}

		token := uniuri.NewLen(10)
		tokenEntry := TokenEntryDb{
			token,
			"",
			credEls[0],
		}
		mongoClient.Database("go-api-app").Collection("tokens").InsertOne(context.TODO(), tokenEntry)
	}
}

func authHandler(ctx *gin.Context) {
	q := AuthQuery{}
	if ctx.ShouldBindQuery(&q) == nil {
		client := retrieveClient(q.Client_id)

		if client == nil {
			ctx.String(401, "Client does not exist")
			return
		}
		if client.Redirect_uri != q.Redirect_uri {
			ctx.String(401, "Uris dont match")
		}
		if q.Response_type != "code" {
			ctx.String(401, "Unsupported resp type")
		}

		code := uniuri.NewLen(8)
		codes[code] = CodeRecord{q.Client_id}

		redirUrl, _ := url.Parse("/approve")
		redirQ := redirUrl.Query()
		redirQ.Add("code", code)
		redirQ.Add("client_id", q.Client_id)
		redirQ.Add("redirect_uri", q.Redirect_uri)
		redirQ.Add("response_type", q.Response_type)
		redirQ.Add("state", q.State)
		redirUrl.RawQuery = redirQ.Encode()

		ctx.Redirect(http.StatusMovedPermanently, redirUrl.String())

		return
	}

	ctx.String(400, "Fail")
}

func approveHandler(ctx *gin.Context) {
	var q ApproveRedirQuery = ApproveRedirQuery{}

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

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Critical. Failed to load env var.")
		return
	}

	mongoConnectionUri := os.Getenv("MONGODB_CONNECTION_URI")
	mongoClient, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoConnectionUri))

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
	g.Run(":9090")
}
