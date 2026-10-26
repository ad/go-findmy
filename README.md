# go-findmy


## for key generation

`go run ./cmd/go-findmy keygen`


## for fetch results

`go run ./cmd/go-findmy fetch`

## auth

`go run ./cmd/go-findmy login` (or `login sms`) with the anisette sidecar on 127.0.0.1:6969. Tokens and the password hash go to `account/`, keep it secret.
