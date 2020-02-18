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

	"github.com/click-stream/shipper/common"
	"github.com/click-stream/shipper/input"
	"github.com/click-stream/shipper/processor"
	"github.com/devopsext/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

// Version of the app
var VERSION = "0.0.4"

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
	URL:    env.Get("SHIPPER_HTTP_URL", "/shipper").(string),
	Listen: env.Get("SHIPPER_HTTP_LISTEN", ":80").(string),
	Cors:   env.Get("SHIPPER_HTTP_CORS", false).(bool),
	Tls:    env.Get("SHIPPER_HTTP_TLS", false).(bool),
	Cert:   env.Get("SHIPPER_HTTP_CERT", "").(string),
	Key:    env.Get("SHIPPER_HTTP_KEY", "").(string),
	Chain:  env.Get("SHIPPER_HTTP_CHAIN", "").(string),

	ExternalHost: env.Get("SHIPPER_HTTP_EXTERNAL_HOST", "").(string),

	OidcEnabled:      env.Get("SHIPPER_HTTP_OIDC_ENABLED", false).(bool),
	OidcClientId:     env.Get("SHIPPER_HTTP_OIDC_CLIENT_ID", "").(string),
	OidcClientSecret: env.Get("SHIPPER_HTTP_OIDC_CLIENT_SECRET", "").(string),
	OidcConfigURL:    env.Get("SHIPPER_HTTP_OIDC_CONFIG_URL", "").(string),
	OidcLoginURL:     env.Get("SHIPPER_HTTP_OIDC_LOGIN_URL", "/login").(string),
	OidcLogoutURL:    env.Get("SHIPPER_HTTP_OIDC_LOGOUT_URL", "/logout").(string),
	OidcCallbackURL:  env.Get("SHIPPER_HTTP_OIDC_CALLBACK_URL", "/callback").(string),
	OidcDefaultURL:   env.Get("SHIPPER_HTTP_OIDC_DEFAULT_URL", "").(string),
	OidcScopes:       env.Get("SHIPPER_HTTP_OIDC_SCOPES", "profile, email, roles, groups").(string),

}

var graphqlOptions = common.GraphqlOptions{
	GraphqlPretty: env.Get("SHIPPER_GRAPHQL_PRETTY", false).(bool),
	GraphqlMode:   env.Get("SHIPPER_GRAPHQL_MODE", "").(string),
}

var clickhouseProcessorOptions = processor.ClickhouseProcessorOptions{

	Host:              env.Get("SHIPPER_CLICKHOUSE_HOST", "").(string),
	Port:              env.Get("SHIPPER_CLICKHOUSE_PORT", 9000).(int),
	User:              env.Get("SHIPPER_CLICKHOUSE_USER", "default").(string),
	Password:          env.Get("SHIPPER_CLICKHOUSE_PASSWORD", "").(string),
	Debug:             env.Get("SHIPPER_CLICKHOUSE_DEBUG", false).(bool),
	URLPattern:        env.Get("SHIPPER_CLICKHOUSE_URL_PATTERN", "/{database}").(string),
	ReadTimeout:       env.Get("SHIPPER_CLICKHOUSE_READ_TIMEOUT", 10).(int),
	DatabasePattern:   env.Get("SHIPPER_CLICKHOUSE_DATABASE_PATTERN", ".*").(string),
	TablePattern:      env.Get("SHIPPER_CLICKHOUSE_TABLE_PATTERN", ".*").(string),
	QueryLimit:        env.Get("SHIPPER_CLICKHOUSE_QUERY_LIMIT", 1000).(int),
	IdentFormat:       env.Get("SHIPPER_CLICKHOUSE_IDENT_FORMAT", "`%s`").(string),
	CacheLifeSeconds:  env.Get("SHIPPER_CLICKHOUSE_CACHE_LIFE_SECONDS", 0).(int),
	CacheCleanSeconds: env.Get("SHIPPER_CLICKHOUSE_CACHE_CLEAN_SECONDS", 0).(int),
	CacheMaxSize:      env.Get("SHIPPER_CLICKHOUSE_CACHE_MAX_SIZE", 0).(int),
	RefreshInterval:   env.Get("SHIPPER_CLICKHOUSE_REFRESH_INTERVAL", 60).(int),
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

		},
		Run: func(cmd *cobra.Command, args []string) {

			log.Info("Booting...")

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

			log.Info("shipper version" + VERSION)

			wg.Wait()
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringVar(&rootOpts.LogFormat, "log-format", rootOpts.LogFormat, "Log format: json, text, stdout")
	flags.StringVar(&rootOpts.LogLevel, "log-level", rootOpts.LogLevel, "Log level: info, warn, error, debug, panic")
	flags.StringVar(&rootOpts.LogTemplate, "log-template", rootOpts.LogTemplate, "Log template")

	flags.StringVar(&rootOpts.PrometheusURL, "prometheus-url", rootOpts.PrometheusURL, "Prometheus endpoint url")
	flags.StringVar(&rootOpts.PrometheusListen, "prometheus-listen", rootOpts.PrometheusListen, "Prometheus listen")

	flags.StringVar(&httpInputOptions.URL, "http-url", httpInputOptions.URL, "Http url")
	flags.StringVar(&httpInputOptions.Listen, "http-listen", httpInputOptions.Listen, "Http listen")
	flags.BoolVar(&httpInputOptions.Cors, "http-cors", httpInputOptions.Cors, "Http CORS true/false")
	flags.BoolVar(&httpInputOptions.Tls, "http-tls", httpInputOptions.Tls, "Http TLS")
	flags.StringVar(&httpInputOptions.Cert, "http-cert", httpInputOptions.Cert, "Http cert file or content")
	flags.StringVar(&httpInputOptions.Key, "http-key", httpInputOptions.Key, "Http key file or content")
	flags.StringVar(&httpInputOptions.Chain, "http-chain", httpInputOptions.Chain, "Http CA chain file or content")
	flags.StringVar(&httpInputOptions.ExternalHost, "http-external-host", httpInputOptions.ExternalHost, "Http external host")

	flags.BoolVar(&httpInputOptions.OidcEnabled, "http-oidc-enabled", httpInputOptions.OidcEnabled, "Http oidc enabled")
	flags.StringVar(&httpInputOptions.OidcClientId, "http-oidc-client-id", httpInputOptions.OidcClientId, "Http oidc client id")
	flags.StringVar(&httpInputOptions.OidcClientSecret, "http-oidc-client-secret", httpInputOptions.OidcClientSecret, "Http oidc client secret")
	flags.StringVar(&httpInputOptions.OidcConfigURL, "http-oidc-config-url", httpInputOptions.OidcConfigURL, "Http oidc config url")
	flags.StringVar(&httpInputOptions.OidcLoginURL, "http-oidc-login-url", httpInputOptions.OidcLoginURL, "Http oidc login url")
	flags.StringVar(&httpInputOptions.OidcLogoutURL, "http-oidc-logout-url", httpInputOptions.OidcLogoutURL, "Http oidc logout url")
	flags.StringVar(&httpInputOptions.OidcCallbackURL, "http-oidc-callback-url", httpInputOptions.OidcCallbackURL, "Http oidc callback url")
	flags.StringVar(&httpInputOptions.OidcDefaultURL, "http-oidc-default-url", httpInputOptions.OidcDefaultURL, "Http oidc default url")
	flags.StringVar(&httpInputOptions.OidcScopes, "http-oidc-scopes-url", httpInputOptions.OidcScopes, "Http oidc scopes")

	flags.BoolVar(&graphqlOptions.GraphqlPretty, "graphql-pretty", graphqlOptions.GraphqlPretty, "Graphql pretty response format")
	flags.StringVar(&graphqlOptions.GraphqlMode, "graphql-mode", graphqlOptions.GraphqlMode, "Graphql mode: GraphiQL, Playground")

	flags.StringVar(&clickhouseProcessorOptions.Host, "clickhouse-host", clickhouseProcessorOptions.Host, "Clickhouse host")
	flags.IntVar(&clickhouseProcessorOptions.Port, "clickhouse-port", clickhouseProcessorOptions.Port, "Clickhouse port")
	flags.StringVar(&clickhouseProcessorOptions.User, "clickhouse-user", clickhouseProcessorOptions.User, "Clickhouse user")
	flags.StringVar(&clickhouseProcessorOptions.Password, "clickhouse-password", clickhouseProcessorOptions.Password, "Clickhouse password")
	flags.BoolVar(&clickhouseProcessorOptions.Debug, "clickhouse-debug", clickhouseProcessorOptions.Debug, "Clickhouse debug")
	flags.StringVar(&clickhouseProcessorOptions.URLPattern, "clickhouse-url-pattern", clickhouseProcessorOptions.URLPattern, "Clickhouse url pattern")
	flags.IntVar(&clickhouseProcessorOptions.ReadTimeout, "clickhouse-read-timeout", clickhouseProcessorOptions.ReadTimeout, "Clickhouse read timeout")
	flags.StringVar(&clickhouseProcessorOptions.DatabasePattern, "clickhouse-database-pattern", clickhouseProcessorOptions.DatabasePattern, "Clickhouse database pattern")
	flags.StringVar(&clickhouseProcessorOptions.TablePattern, "clickhouse-table-pattern", clickhouseProcessorOptions.TablePattern, "Clickhouse table pattern")
	flags.IntVar(&clickhouseProcessorOptions.QueryLimit, "clickhouse-query-limit", clickhouseProcessorOptions.QueryLimit, "Clickhouse query limit")
	flags.StringVar(&clickhouseProcessorOptions.IdentFormat, "clickhouse-ident-format", clickhouseProcessorOptions.IdentFormat, "Clickhouse ident format")
	flags.IntVar(&clickhouseProcessorOptions.CacheLifeSeconds, "clickhouse-cache-life-seconds", clickhouseProcessorOptions.CacheLifeSeconds, "Clickhouse cache life seconds")
	flags.IntVar(&clickhouseProcessorOptions.CacheCleanSeconds, "clickhouse-cache-clean-seconds", clickhouseProcessorOptions.CacheCleanSeconds, "Clickhouse cache clean seconds")
	flags.IntVar(&clickhouseProcessorOptions.CacheMaxSize, "clickhouse-cache-max-size", clickhouseProcessorOptions.CacheMaxSize, "Clickhouse cache max size in MB")
	flags.IntVar(&clickhouseProcessorOptions.RefreshInterval, "clickhouse-refresh-interval", clickhouseProcessorOptions.RefreshInterval, "Clickhouse refresh interval in seconds")

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(VERSION)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
