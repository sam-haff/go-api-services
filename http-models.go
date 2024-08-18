package goapp

type AuthQuery struct {
	Client_id     string `form:"client_id" json:"client_id"`
	Redirect_uri  string `form:"redirect_uri" json:"redirect_uri"`
	State         string `form:"state" json:"state"`
	Response_type string `form:"response_type" json:"response_type"`
}

type ApproveRedirQuery struct {
	Code          string `form:"code" json:"code"`
	Client_id     string `form:"client_id" json:"client_id"`
	Redirect_uri  string `form:"redirect_uri" json:"redirect_uri"`
	State         string `form:"state" json:"state"`
	Response_type string `form:"response_type" json:"response_type"`
}

type TokenRequestBody struct {
	GrantType   string `form:"grant_type" json:"grant_type"`
	Code        string `form:"code" json:"code"`
	RedirectUri string `form:"redirect_uri" json:"redirect_uri"`
	State       string `form:"state" json:"state"`
}

type TokenResponse struct {
	TokenType    string `form:"token_type" json:"token_type"`
	AccessToken  string `form:"access_token json:"access_token"`
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
}
