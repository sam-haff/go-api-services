package main

type TokenEntryDb struct {
	AccessToken  string `bson:"access_token"`
	RefreshToken string `bson:"refresh_token"`
	ClientId     string `bson:"client_id"`
}
