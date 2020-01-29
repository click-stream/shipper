package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"

	"github.com/clickstreampro/shipper/common"
	"github.com/clickstreampro/shipper/input"
	"github.com/clickstreampro/shipper/processor"
	"github.com/devopsext/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

// Version of the app
var VERSION = "unknown"

var log = utils.GetLog()
var env = utils.GetEnvironment()

type rootOptions struct {
	LogFormat   string
	LogLevel    string
	LogTemplate string

	PrometheusURL    string
	PrometheusListen string
}

var rootOpts = rootOptions{

	LogFormat:   env.Get("SHIPPER_LOG_FORMAT", "text").(string),
	LogLevel:    env.Get("SHIPPER_LOG_LEVEL", "info").(string),
	LogTemplate: env.Get("SHIPPER_LOG_TEMPLATE", "{{.func}} [{{.line}}]: {{.msg}}").(string),

	PrometheusURL:    env.Get("SHIPPER_PROMETHEUS_URL", "/metrics").(string),
	PrometheusListen: env.Get("SHIPPER_PROMETHEUS_LISTEN", "127.0.0.1:8080").(string),
}

var httpInputOptions = input.HttpInputOptions{

	HttpURL:    env.Get("SHIPPER_HTTP_URL", "/shipper").(string),
	HttpListen: env.Get("SHIPPER_HTTP_LISTEN", ":80").(string),
	HttpTls:    env.Get("SHIPPER_HTTP_TLS", false).(bool),
	HttpCert:   env.Get("SHIPPER_HTTP_CERT", "").(string),
	HttpKey:    env.Get("SHIPPER_HTTP_KEY", "").(string),
	HttpChain:  env.Get("SHIPPER_HTTP_CHAIN", "").(string),

	HttpExternalHost: env.Get("SHIPPER_HTTP_EXTERNAL_HOST", "").(string),

	HttpOidcEnabled:      env.Get("SHIPPER_HTTP_OIDC_ENABLED", false).(bool),
	HttpOidcClientId:     env.Get("SHIPPER_HTTP_OIDC_CLIENT_ID", "").(string),
	HttpOidcClientSecret: env.Get("SHIPPER_HTTP_OIDC_CLIENT_SECRET", "").(string),
	HttpOidcConfigURL:    env.Get("SHIPPER_HTTP_OIDC_CONFIG_URL", "").(string),
	HttpOidcLoginURL:     env.Get("SHIPPER_HTTP_OIDC_LOGIN_URL", "/login").(string),
	HttpOidcLogoutURL:    env.Get("SHIPPER_HTTP_OIDC_LOGOUT_URL", "/logout").(string),
	HttpOidcCallbackURL:  env.Get("SHIPPER_HTTP_OIDC_CALLBACK_URL", "/callback").(string),
	HttpOidcDefaultURL:   env.Get("SHIPPER_HTTP_OIDC_DEFAULT_URL", "").(string),
	HttpOidcScopes:       env.Get("SHIPPER_HTTP_OIDC_SCOPES", "profile, email, roles, groups").(string),
}

var graphqlOptions = common.GraphqlOptions{
	GraphqlPretty: env.Get("SHIPPER_GRAPHQL_PRETTY", false).(bool),
	GraphqlMode:   env.Get("SHIPPER_GRAPHQL_MODE", "").(string),
}

var clickhouseProcessorOptions = processor.ClickhouseProcessorOptions{

	ClickhouseHost:              env.Get("SHIPPER_CLICKHOUSE_HOST", "").(string),
	ClickhousePort:              env.Get("SHIPPER_CLICKHOUSE_PORT", 9000).(int),
	ClickhouseUser:              env.Get("SHIPPER_CLICKHOUSE_USER", "default").(string),
	ClickhousePassword:          env.Get("SHIPPER_CLICKHOUSE_PASSWORD", "").(string),
	ClickhouseDebug:             env.Get("SHIPPER_CLICKHOUSE_DEBUG", false).(bool),
	ClickhouseURLPattern:        env.Get("SHIPPER_CLICKHOUSE_URL_PATTERN", "/{database}").(string),
	ClickhouseReadTimeout:       env.Get("SHIPPER_CLICKHOUSE_READ_TIMEOUT", 10).(int),
	ClickhouseDatabasePattern:   env.Get("SHIPPER_CLICKHOUSE_DATABASE_PATTERN", "").(string),
	ClickhouseTablePattern:      env.Get("SHIPPER_CLICKHOUSE_TABLE_PATTERN", "").(string),
	ClickhouseQueryLimit:        env.Get("SHIPPER_CLICKHOUSE_QUERY_LIMIT", 1000).(int),
	ClickhouseIdentFormat:       env.Get("SHIPPER_CLICKHOUSE_IDENT_FORMAT", "`%s`").(string),
	ClickhouseCacheLifeSeconds:  env.Get("SHIPPER_CLICKHOUSE_CACHE_LIFE_SECONDS", 0).(int),
	ClickhouseCacheCleanSeconds: env.Get("SHIPPER_CLICKHOUSE_CACHE_CLEAN_SECONDS", 0).(int),
	ClickhouseCacheMaxSize:      env.Get("SHIPPER_CLICKHOUSE_CACHE_MAX_SIZE", 0).(int),
}

func startMetrics(wg *sync.WaitGroup) {

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()

		log.Info("Start metrics...")

		http.Handle(rootOpts.PrometheusURL, promhttp.Handler())

		listener, err := net.Listen("tcp", rootOpts.PrometheusListen)
		if err != nil {
			log.Panic(err)
		}

		log.Info("Metrics are up. Listening...")

		err = http.Serve(listener, nil)
		if err != nil {
			log.Panic(err)
		}

	}(wg)
}

func interceptSyscall() {

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	go func() {
		<-c
		log.Info("Exiting...")
		os.Exit(1)
	}()
}

func Execute() {

	rootCmd := &cobra.Command{
		Use:   "shipper",
		Short: "Shipper",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			log.CallInfo = true
			log.Init(rootOpts.LogFormat, rootOpts.LogLevel, rootOpts.LogTemplate)

			var wg sync.WaitGroup

			startMetrics(&wg)

			var clickhouseProcessor common.Processor = processor.NewClickhouseProcessor(clickhouseProcessorOptions, graphqlOptions)
			if reflect.ValueOf(clickhouseProcessor).IsNil() {
				log.Panic("Clickhouse processor is invalid. Terminating...")
			}

			processors := common.NewProcessors()
			processors.Add(&clickhouseProcessor)

			var httpInput common.Input = input.NewHttpInput(httpInputOptions, processors)
			if reflect.ValueOf(httpInput).IsNil() {
				log.Panic("Http input is invalid. Terminating...")
			}

			inputs := common.NewInputs()
			inputs.Add(&httpInput)

			inputs.Start(&wg)

			wg.Wait()
		},
		Run: func(cmd *cobra.Command, args []string) {

			log.Info("Booting...")
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringVar(&rootOpts.LogFormat, "log-format", rootOpts.LogFormat, "Log format: json, text, stdout")
	flags.StringVar(&rootOpts.LogLevel, "log-level", rootOpts.LogLevel, "Log level: info, warn, error, debug, panic")
	flags.StringVar(&rootOpts.LogTemplate, "log-template", rootOpts.LogTemplate, "Log template")

	flags.StringVar(&rootOpts.PrometheusURL, "prometheus-url", rootOpts.PrometheusURL, "Prometheus endpoint url")
	flags.StringVar(&rootOpts.PrometheusListen, "prometheus-listen", rootOpts.PrometheusListen, "Prometheus listen")

	flags.StringVar(&httpInputOptions.HttpURL, "http-url", httpInputOptions.HttpURL, "Http url")
	flags.StringVar(&httpInputOptions.HttpListen, "http-listen", httpInputOptions.HttpListen, "Http listen")
	flags.BoolVar(&httpInputOptions.HttpTls, "http-tls", httpInputOptions.HttpTls, "Http TLS")
	flags.StringVar(&httpInputOptions.HttpCert, "http-cert", httpInputOptions.HttpCert, "Http cert file or content")
	flags.StringVar(&httpInputOptions.HttpKey, "http-key", httpInputOptions.HttpKey, "Http key file or content")
	flags.StringVar(&httpInputOptions.HttpChain, "http-chain", httpInputOptions.HttpChain, "Http CA chain file or content")
	flags.StringVar(&httpInputOptions.HttpExternalHost, "http-external-host", httpInputOptions.HttpExternalHost, "Http external host")

	flags.BoolVar(&httpInputOptions.HttpOidcEnabled, "http-oidc-enabled", httpInputOptions.HttpOidcEnabled, "Http oidc enabled")
	flags.StringVar(&httpInputOptions.HttpOidcClientId, "http-oidc-client-id", httpInputOptions.HttpOidcClientId, "Http oidc client id")
	flags.StringVar(&httpInputOptions.HttpOidcClientSecret, "http-oidc-client-secret", httpInputOptions.HttpOidcClientSecret, "Http oidc client secret")
	flags.StringVar(&httpInputOptions.HttpOidcConfigURL, "http-oidc-config-url", httpInputOptions.HttpOidcConfigURL, "Http oidc config url")
	flags.StringVar(&httpInputOptions.HttpOidcLoginURL, "http-oidc-login-url", httpInputOptions.HttpOidcLoginURL, "Http oidc login url")
	flags.StringVar(&httpInputOptions.HttpOidcLogoutURL, "http-oidc-logout-url", httpInputOptions.HttpOidcLogoutURL, "Http oidc logout url")
	flags.StringVar(&httpInputOptions.HttpOidcCallbackURL, "http-oidc-callback-url", httpInputOptions.HttpOidcCallbackURL, "Http oidc callback url")
	flags.StringVar(&httpInputOptions.HttpOidcDefaultURL, "http-oidc-default-url", httpInputOptions.HttpOidcDefaultURL, "Http oidc default url")
	flags.StringVar(&httpInputOptions.HttpOidcScopes, "http-oidc-scopes-url", httpInputOptions.HttpOidcScopes, "Http oidc scopes")

	flags.BoolVar(&graphqlOptions.GraphqlPretty, "graphql-pretty", graphqlOptions.GraphqlPretty, "Graphql pretty response format")
	flags.StringVar(&graphqlOptions.GraphqlMode, "graphql-mode", graphqlOptions.GraphqlMode, "Graphql mode: GraphiQL, Playground")

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(VERSION)
		},
	})

	//rootCmd.AddCommand(GetWebsiteCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
