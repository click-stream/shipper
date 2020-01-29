package input

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/clickstreampro/shipper/common"
	"github.com/devopsext/utils"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

var httpInputRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "shipper_http_input_requests",
	Help: "Count of all http input requests",
}, []string{"shipper_http_input_url"})

type HttpInputOptions struct {
	HttpURL              string
	HttpListen           string
	HttpTls              bool
	HttpCert             string
	HttpKey              string
	HttpChain            string
	HttpExternalHost     string
	HttpOidcEnabled      bool
	HttpOidcClientId     string
	HttpOidcClientSecret string
	HttpOidcConfigURL    string
	HttpOidcLoginURL     string
	HttpOidcLogoutURL    string
	HttpOidcCallbackURL  string
	HttpOidcDefaultURL   string
	HttpOidcScopes       string
}

type HttpInput struct {
	options    HttpInputOptions
	processors *common.Processors
}

func (h *HttpInput) setupCors(w http.ResponseWriter, req *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func counterFunc(callback func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		httpInputRequests.WithLabelValues(r.URL.Path).Inc()
		callback(w, r)
	})
}

func (h *HttpInput) getUrl(s string) string {

	return fmt.Sprintf("%s%s", h.options.HttpURL, s)
}

func (h *HttpInput) Start(wg *sync.WaitGroup) {

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()

		log.Info("Start http input...")

		var caPool *x509.CertPool
		var certificates []tls.Certificate

		if h.options.HttpTls {

			// load certififcate
			var cert []byte
			if _, err := os.Stat(h.options.HttpCert); err == nil {

				cert, err = ioutil.ReadFile(h.options.HttpCert)
				if err != nil {
					log.Panic(err)
				}
			} else {
				cert = []byte(h.options.HttpCert)
			}

			// load key
			var key []byte
			if _, err := os.Stat(h.options.HttpKey); err == nil {

				key, err = ioutil.ReadFile(h.options.HttpKey)
				if err != nil {
					log.Panic(err)
				}
			} else {
				key = []byte(h.options.HttpKey)
			}

			// make pair from certificate and pair
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				log.Panic(err)
			}

			certificates = append(certificates, pair)

			// load CA chain
			var chain []byte
			if _, err := os.Stat(h.options.HttpChain); err == nil {

				chain, err = ioutil.ReadFile(h.options.HttpChain)
				if err != nil {
					log.Panic(err)
				}
			} else {
				chain = []byte(h.options.HttpChain)
			}

			// make pool of chains
			caPool = x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(chain) {
				log.Debug("CA chain is invalid")
			}
		}

		router := mux.NewRouter()

		if h.processors != nil {

			for _, p := range h.processors.Items() {

				url := h.getUrl((*p).GetUrlPattern())
				var o *HttpOidc

				if h.options.HttpOidcEnabled && !utils.IsEmpty(h.options.HttpOidcConfigURL) {
					o = NewHttpOidc(&h.options)
				}

				if o != nil {

					router.HandleFunc(h.getUrl(h.options.HttpOidcLoginURL), counterFunc(o.oidcLogin))
					router.HandleFunc(h.getUrl(h.options.HttpOidcLogoutURL), counterFunc(o.oidcLogout))
					router.HandleFunc(h.getUrl(h.options.HttpOidcCallbackURL), counterFunc(o.oidcCallback))
					router.HandleFunc(url, counterFunc(o.oidcCheck((*p).HandleHttpRequest)))
				} else {
					router.HandleFunc(url, counterFunc((*p).HandleHttpRequest))
				}
			}
		}

		listener, err := net.Listen("tcp", h.options.HttpListen)
		if err != nil {
			log.Panic(err)
		}

		log.Info("Http input is up. Listening...")

		srv := &http.Server{Handler: router}

		if h.options.HttpTls {

			srv.TLSConfig = &tls.Config{
				Certificates: certificates,
				RootCAs:      caPool,
			}

			err = srv.ServeTLS(listener, "", "")
			if err != nil {
				log.Panic(err)
			}
		} else {
			err = srv.Serve(listener)
			if err != nil {
				log.Panic(err)
			}
		}

	}(wg)
}

func NewHttpInput(options HttpInputOptions, processors *common.Processors) *HttpInput {

	return &HttpInput{
		options:    options,
		processors: processors,
	}
}

func init() {
	prometheus.Register(httpInputRequests)
}
