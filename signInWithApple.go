package signinwithapple

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

//SigninConfig main apple signin config, set your information use updaetConfig()
type SigninConfig struct {
	TeamID      string
	ClientID    string
	RedirectURL string
	KeyID       string
	KeyPath     string
	GrantType   string //authorization_code or refresh_token
}

// ResponseToken from apple REST-API (https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse)
type ResponseToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

const authTokenURL = "https://appleid.apple.com/auth/token"

//getClientSecret //https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple
func (s *SigninConfig) getClientSecret() (string, error) {

	certKey, err := loadP8File(s.KeyPath)
	if err != nil {
		return "", errors.Wrap(err, "[error] laod p8 file failed\n")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": s.TeamID,
		"iat": time.Now().Unix(),
		// constraint: exp - iat <= 180 days
		"exp": time.Now().Unix() + 600,
		"aud": "https://appleid.apple.com",
		"sub": s.ClientID,
	})

	token.Header = map[string]interface{}{
		"alg": "ES256",
		"kid": s.KeyID,
	}

	tokenStr, err := token.SignedString(certKey)
	if err != nil {
		return "", errors.Wrap(err, "[error] jwt token str failed\n")
	}
	return tokenStr, nil
}

//RequestAuthToken https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
func (s *SigninConfig) RequestAuthToken(authCode string) (*ResponseToken, error) {

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	secret, err := s.getClientSecret()
	if err != nil {
		return nil, errors.WithMessage(err, "[error] get client secret failed\n")
	}

	params := map[string]string{"client_id": s.ClientID,
		"client_secret": secret,
		"code":          authCode,
		"grant_type":    s.GrantType,
		"redirect_uri":  s.RedirectURL,
	}

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	request, err := http.NewRequest("POST", authTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.WithMessage(err, "[error] request auth token failed\n")
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.WithMessage(err, "[error] response error\n")
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("[error] signin with apple response = %s\n", response.Status))
	}

	var responseToken ResponseToken
	err = json.NewDecoder(response.Body).Decode(&responseToken)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("[error] signin with apple response decode failed - %d\n", err))
	}

	//fmt.Printf("%v\n", responseToken)

	return &responseToken, nil
}

//loadP8File ...
func loadP8File(path string) (interface{}, error) {

	mydir, err := os.Getwd()
	if err != nil {
		return nil, errors.Wrap(err, "[error] current dir not found\n")
	}

	mydir = fmt.Sprintf("%s%s", mydir, path)

	data, err := ioutil.ReadFile(mydir)
	if err != nil {
		return nil, errors.Wrap(err, "[error] read p8 file fialed\n")
	}

	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.Wrap(err, "[error] pem decode fialed\n")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "[error] x509 parse fialed\n")
	}

	return key, nil
}
