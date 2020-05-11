# Golang-Signin-with-Apple
This project use the Sign in with Apple REST API to communicate with Apple servers

## Installation

```
go mod init
github.com/jswdev/signinwithapple v1.0.0
```   
```
import "github.com/jswdev/signinwithapple"
```


## Example

Create a Private Key for Client Authentication from [apple developer](https://developer.apple.com/account/resources/authkeys/list) and   
download it to your main folder and rename to keyid.p8 (ex: 1234A56XQ6.p8)



```
package main

import (
	"fmt"
	signin "github.com/jswdev/signinwithapple"
)

func main() {

	cfg := signin.SigninConfig{
		TeamID:      (your apple team id),
		ClientID:    (your client id),
		RedirectURL: "https://example-app.com/redirect",
		KeyID:       (your key id),
		KeyPath:     (your key path),
		GrantType:   "authorization_code",
	}

	authToken, err := cfg.RequestAuthToken(authcode)
	if err != nil {

		fmt.Printf("%v", err)
		//%s    print the error. If the error has a Cause it will be printed recursively.
		//%v    see %s
		//%+v   extended format. Each Frame of the error's StackTrace will be printed in detail.
		return
	}
}

```


## Reference
https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api
https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple
https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
