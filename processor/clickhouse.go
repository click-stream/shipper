package processor

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/click-stream/shipper/common"
	"github.com/devopsext/utils"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"

	"github.com/graphql-go/graphql"
	ast "github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/handler"

	"github.com/allegro/bigcache"

	// Add as a driver
	_ "github.com/ClickHouse/clickhouse-go"
	"github.com/prometheus/client_golang/prometheus"
)

var clickhouseProcessorRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "shipper_clickhouse_processor_requests",
	Help: "Count of all clickhouse processor requests",
}, []string{})

type ClickhouseProcessorOptions struct {
	ClickhouseHost              string
	ClickhousePort              int
	ClickhouseUser              string
	ClickhousePassword          string
	ClickhouseDebug             bool
	ClickhouseURLPattern        string
	ClickhouseReadTimeout       int
	ClickhouseDatabasePattern   string
	ClickhouseTablePattern      string
	ClickhouseQueryLimit        int
	ClickhouseIdentFormat       string
	ClickhouseCacheLifeSeconds  int
	ClickhouseCacheCleanSeconds int
	ClickhouseCacheMaxSize      int
}

type ClickhouseProcessor struct {
	db         *sqlx.DB
	handlers   map[string]*handler.Handler
	options    ClickhouseProcessorOptions
	playground bool
}

func (cp *ClickhouseProcessor) GetUrlPattern() string {

	return cp.options.ClickhouseURLPattern
}

func (cp *ClickhouseProcessor) HandleHttpRequest(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	ident := vars["database"]

	h := cp.handlers[ident]
	if h == nil {

		log.Error("Not found")
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// fix default Playground
	if cp.playground {
		acceptHeader := r.Header.Get("Accept")
		_, raw := r.URL.Query()["raw"]
		if !raw && !strings.Contains(acceptHeader, "application/json") && strings.Contains(acceptHeader, "text/html") {
			renderPlayground(w, r)
			return
		}
	}

	h.ContextHandler(r.Context(), w, r)
}

func hasElement(s string, arr []string) bool {
	for _, s1 := range arr {
		if s1 == s {
			return true
		}
	}
	return false
}

func prepareIdent(ident string, format string) string {

	return fmt.Sprintf(format, ident)
}

func getFieldsString(p graphql.ResolveParams, format string) string {

	r := ""

	for _, info := range p.Info.FieldASTs {

		set1 := info.SelectionSet
		if set1 == nil {
			continue
		}

		for _, selection := range set1.Selections {

			if reflect.TypeOf(selection).Name() == "Field" {
				continue
			}

			f, ok := selection.(*ast.Field)
			if !ok || f == nil {
				continue
			}

			s := f.Name.Value

			if !utils.IsEmpty(s) {

				if utils.IsEmpty(r) {
					r = prepareIdent(s, format)
				} else {
					r = fmt.Sprintf("%s, %s", r, prepareIdent(s, format))
				}
			}
		}
	}

	return r
}

var exclude = []string{"limit", "offset", "order"}
var operationFormats = map[string]string{
	"Match": "match(%s,%v) = 1",
	"EQ":    "%s = %v",
	"NE":    "%s != %v",
	"LT":    "%s < %v",
	"LE":    "%s <= %v",
	"GT":    "%s > %v",
	"GE":    "%s >= %v",
}

func getOperationFormat(name string) (string, string) {

	for op, f := range operationFormats {

		index := strings.LastIndex(name, op)
		if index >= 0 {
			name = name[:index]
			if utils.IsEmpty(name) {
				continue
			}
			return name, f
		}
	}

	return name, "%s = %s"
}

//var timeKind = reflect.TypeOf(time.Time{}).Kind()

func getWhereString(p graphql.ResolveParams, format string) string {

	r := ""

	for name, value := range p.Args {

		if hasElement(name, exclude) {
			continue
		}

		s := ""
		name, of := getOperationFormat(name)
		f := prepareIdent(name, format)

		switch t := reflect.TypeOf(value); t.Kind() {
		case reflect.Int,
			reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:

			if value != nil {

				s = fmt.Sprintf(of, f, value)
			}
			/*		case timeKind:

					t, ok := value.(time.Time)
					if ok {
						s = fmt.Sprintf(of, f, fmt.Sprintf("'%s'", t.Format("2006-01-02 15:04:05")))
					}
			*/
		default:

			value, ok := value.(string)
			if ok {
				s = fmt.Sprintf(of, f, fmt.Sprintf("'%s'", value))
			}
		}

		if !utils.IsEmpty(s) {

			if utils.IsEmpty(r) {
				r = s
			} else {
				r = fmt.Sprintf("%s AND %s", r, s)
			}
		}
	}
	return r
}

func getOrderString(orders []interface{}) string {

	r := ""

	for _, order := range orders {

		s, ok := order.(string)
		if !ok {
			continue
		}

		if !utils.IsEmpty(s) {

			if utils.IsEmpty(r) {
				r = s
			} else {
				r = fmt.Sprintf("%s, %s", r, s)
			}
		}
	}
	return r
}

func setArgsWithType(name string, description string, args graphql.FieldConfigArgument, aft graphql.Input) {

	args[fmt.Sprintf("%sMatch", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Match for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sEQ", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Equal for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sNE", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Not equal for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sLT", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Less than for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sLE", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Less than or equal for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sGT", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Greater than for %s", name),
		Type:        aft,
	}

	args[fmt.Sprintf("%sGE", name)] = &graphql.ArgumentConfig{
		Description: fmt.Sprintf("Greater than or equal for %s", name),
		Type:        aft,
	}
}

func makeField(db *sqlx.DB, cache *bigcache.BigCache, options ClickhouseProcessorOptions, database string, table string) *graphql.Field {

	query := fmt.Sprintf("SELECT name, type, comment FROM system.columns WHERE database='%s' AND table='%s'", database, table)

	var items []struct {
		Name    string `db:"name"`
		Type    string `db:"type"`
		Comment string `db:"comment"`
	}

	if err := db.Select(&items, query); err != nil {
		log.Error(err)
		return nil
	}

	if len(items) == 0 {
		log.Error("No fields found.")
		return nil
	}

	objFields := make(graphql.Fields)
	queryArgs := make(graphql.FieldConfigArgument)
	orderValues := make(graphql.EnumValueConfigMap)

	for _, item := range items {

		if hasElement(item.Name, exclude) {
			continue
		}

		var aft *graphql.Scalar

		switch t := item.Type; t {
		case "Date":
			aft = graphql.String
		case "Int8", "Int16", "Int32":
			aft = common.Int32
		case "Int64":
			aft = common.Int64
		case "UInt8", "UInt16", "UInt32":
			aft = common.UInt32
		case "UInt64":
			aft = common.UInt64
		case "Float32", "Float64":
			aft = graphql.Float
		default:
			aft = graphql.String
		}

		ident := prepareIdent(item.Name, options.ClickhouseIdentFormat)
		orderValues[fmt.Sprintf("%sASC", item.Name)] = &graphql.EnumValueConfig{Value: fmt.Sprintf("%s ASC", ident)}
		orderValues[fmt.Sprintf("%sDESC", item.Name)] = &graphql.EnumValueConfig{Value: fmt.Sprintf("%s DESC", ident)}

		setArgsWithType(item.Name, item.Comment, queryArgs, aft)

		field := graphql.Field{
			Description: item.Comment,
			Type:        aft,
		}
		objFields[item.Name] = &field
	}

	var obj = graphql.NewObject(graphql.ObjectConfig{
		Name:   table,
		Fields: objFields,
	})

	queryArgs["limit"] = &graphql.ArgumentConfig{
		Type:        graphql.Int,
		Description: fmt.Sprintf("Query limit (default: %d)", options.ClickhouseQueryLimit),
	}

	queryArgs["offset"] = &graphql.ArgumentConfig{
		Type:        graphql.Int,
		Description: fmt.Sprintf("Query offset (default: %d)", 0),
	}

	orderConfig := graphql.EnumConfig{
		Name:   fmt.Sprintf("%sOrder", table),
		Values: orderValues,
	}

	queryArgs["order"] = &graphql.ArgumentConfig{
		Type: graphql.NewList(graphql.NewEnum(orderConfig)),
	}

	gob.Register(time.Time{})

	r := &graphql.Field{
		Type: graphql.NewList(obj),
		Args: queryArgs,
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {

			fields := getFieldsString(p, options.ClickhouseIdentFormat)
			if utils.IsEmpty(fields) {
				fields = "*"
			}

			where := getWhereString(p, options.ClickhouseIdentFormat)
			if !utils.IsEmpty(where) {
				where = fmt.Sprintf(" WHERE %s", where)
			}

			order := ""
			pArg := p.Args["order"]

			if pArg != nil {

				orders, ok := pArg.([]interface{})
				if ok {
					order = getOrderString(orders)
					if !utils.IsEmpty(order) {
						order = fmt.Sprintf(" ORDER BY %s", order)
					}
				}
			}

			limit, ok := p.Args["limit"].(int)
			if !ok || (ok && limit <= 0) {
				limit = options.ClickhouseQueryLimit
			}

			offset, ok := p.Args["offset"].(int)
			if !ok || (ok && offset < 0) {
				offset = 0
			}

			query := fmt.Sprintf("SELECT %s FROM %s.%s%s%s LIMIT %d OFFSET %d",
				fields, prepareIdent(database, options.ClickhouseIdentFormat),
				prepareIdent(table, options.ClickhouseIdentFormat), where, order, limit, offset)

			var r []map[string]interface{}

			if cache != nil {

				entry, err := cache.Get(query)
				if err == nil {

					buf := bytes.NewBuffer(entry)
					dec := gob.NewDecoder(buf)
					err = dec.Decode(&r)
					if err != nil {
						log.Warn(err)
					} else {
						return r, nil
					}
				}
			}

			rows, err := db.Queryx(query)
			if err != nil {
				log.Error(err)
				return nil, err
			}
			defer rows.Close()

			for rows.Next() {

				m := make(map[string]interface{})

				err := rows.MapScan(m)
				if err != nil {
					log.Error(err)
					return nil, err
				}
				r = append(r, m)
			}

			if cache != nil {

				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				err = enc.Encode(r)
				if err == nil {
					cache.Set(query, buf.Bytes())
				} else {
					log.Warn(err)
				}
			}

			return r, nil
		},
	}

	return r
}

func makeHandler(db *sqlx.DB, cache *bigcache.BigCache, clickhouseOptions ClickhouseProcessorOptions, graphqlOptions common.GraphqlOptions, database string) *handler.Handler {

	query := fmt.Sprintf("SELECT name FROM system.tables WHERE database='%s' AND match(name,'%s')=1", database, clickhouseOptions.ClickhouseDatabasePattern)

	var items []struct {
		Name string `db:"name"`
	}

	if err := db.Select(&items, query); err != nil {
		log.Error(err)
		return nil
	}

	if len(items) == 0 {
		log.Error("No tables found.")
		return nil
	}

	queryFields := make(graphql.Fields)

	for _, item := range items {

		queryFields[item.Name] = makeField(db, cache, clickhouseOptions, database, item.Name)
	}

	rootQuery := graphql.ObjectConfig{Name: "Query", Fields: queryFields}
	schemaConfig := graphql.SchemaConfig{Query: graphql.NewObject(rootQuery)}
	schema, err := graphql.NewSchema(schemaConfig)

	if err != nil {
		log.Error(err)
		return nil
	}

	config := &handler.Config{
		Schema: &schema,
	}

	graphqlOptions.PrepareHandlerConfig(config)

	// disable default Playground is it's on
	config.Playground = false

	return handler.New(config)
}

func generateHandlers(db *sqlx.DB, cache *bigcache.BigCache, clickhouseOptions ClickhouseProcessorOptions, graphqlOptions common.GraphqlOptions) map[string]*handler.Handler {

	r := make(map[string]*handler.Handler)

	query := fmt.Sprintf("SELECT name FROM system.databases WHERE match(name,'%s')=1", clickhouseOptions.ClickhouseDatabasePattern)

	var items []struct {
		Name string `db:"name"`
	}

	if err := db.Select(&items, query); err != nil {
		log.Error(err)
		return r
	}

	for _, item := range items {

		r[item.Name] = makeHandler(db, cache, clickhouseOptions, graphqlOptions, item.Name)
	}

	return r
}

func getDB(options ClickhouseProcessorOptions) *sqlx.DB {

	url := fmt.Sprintf("tcp://%s:%d?debug=%s&username=%s&password=%s&read_timeout=%d",
		options.ClickhouseHost, options.ClickhousePort, strconv.FormatBool(options.ClickhouseDebug),
		options.ClickhouseUser, options.ClickhousePassword, options.ClickhouseReadTimeout)

	db, err := sqlx.Open("clickhouse", url)
	if err != nil {
		log.Error(err)
		return nil
	}

	return db
}

func NewClickhouseProcessor(processorOptions ClickhouseProcessorOptions, graphqlOptions common.GraphqlOptions) *ClickhouseProcessor {

	db := getDB(processorOptions)
	if db == nil {
		return nil
	}

	var cache *bigcache.BigCache
	var err error

	if processorOptions.ClickhouseCacheLifeSeconds >= 0 {

		config := bigcache.DefaultConfig(time.Duration(processorOptions.ClickhouseCacheLifeSeconds) * time.Second)
		config.CleanWindow = time.Duration(processorOptions.ClickhouseCacheCleanSeconds) * time.Second
		config.HardMaxCacheSize = processorOptions.ClickhouseCacheMaxSize

		cache, err = bigcache.NewBigCache(config)
		if err != nil {
			log.Warn(err)
		}
	}

	handlers := generateHandlers(db, cache, processorOptions, graphqlOptions)
	if len(handlers) == 0 {
		return nil
	}

	return &ClickhouseProcessor{
		db:         db,
		handlers:   handlers,
		options:    processorOptions,
		playground: graphqlOptions.IsPlayground(),
	}
}

func init() {
	prometheus.Register(clickhouseProcessorRequests)
}
