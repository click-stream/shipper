package common

import "net/http"

type Processor interface {
	GetUrlPattern() string
	HandleHttpRequest(w http.ResponseWriter, r *http.Request)
}
