module github.com/click-stream/shipper

go 1.13

require (
	github.com/ClickHouse/clickhouse-go v1.3.13
	github.com/allegro/bigcache v1.2.1
	github.com/click-stream/ratecounter v0.2.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/devopsext/utils v0.0.3
	github.com/gorilla/mux v1.7.3
	github.com/graphql-go/graphql v0.7.8
	github.com/graphql-go/handler v0.2.3

	github.com/jasonlvhit/gocron v0.0.0-20191228163020-98b59b546dee
	github.com/jmoiron/sqlx v1.2.0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/client_golang v1.4.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d // indirect
	golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200124204421-9fbb57f87de9 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect

)

replace github.com/jasonlvhit/gocron => github.com/click-stream/gocron v1.0.0
