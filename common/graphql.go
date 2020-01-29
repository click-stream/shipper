package common

import (
	"math"
	"strconv"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/handler"
)

type GraphqlOptions struct {
	GraphqlPretty bool
	GraphqlMode   string
}

func (o *GraphqlOptions) IsPlayground() bool {

	return o.GraphqlMode == "Playground"
}

func (o *GraphqlOptions) PrepareHandlerConfig(config *handler.Config) {

	if config != nil {
		config.Pretty = o.GraphqlPretty
		config.GraphiQL = o.GraphqlMode == "GraphiQL"
		config.Playground = o.IsPlayground()
	}
}

func coerceAnyInt(value interface{}) interface{} {
	switch value := value.(type) {
	case bool:
		if value == true {
			return 1
		}
		return 0
	case *bool:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case int:
		if value < int(math.MinInt32) || value > int(math.MaxInt32) {
			return nil
		}
		return value
	case *int:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case int8:
		return int8(value)
	case *int8:
		if value == nil {
			return nil
		}
		return int8(*value)
	case int16:
		return int16(value)
	case *int16:
		if value == nil {
			return nil
		}
		return int16(*value)
	case int32:
		return int32(value)
	case *int32:
		if value == nil {
			return nil
		}
		return int32(*value)
	case int64:
		if value < int64(math.MinInt64) || value > int64(math.MaxInt64) {
			return nil
		}
		return int64(value)
	case *int64:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case uint:
		if value > math.MaxUint64 {
			return nil
		}
		return uint(value)
	case *uint:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case uint8:
		return uint8(value)
	case *uint8:
		if value == nil {
			return nil
		}
		return uint8(*value)
	case uint16:
		return uint16(value)
	case *uint16:
		if value == nil {
			return nil
		}
		return uint16(*value)
	case uint32:
		if value > uint32(math.MaxUint32) {
			return nil
		}
		return uint32(value)
	case *uint32:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case uint64:
		if value > uint64(math.MaxUint64) {
			return nil
		}
		return uint64(value)
	case *uint64:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case float32:
		if value < float32(math.MinInt32) || value > float32(math.MaxInt32) {
			return nil
		}
		return int(value)
	case *float32:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case float64:
		if value < float64(math.MinInt64) || value > float64(math.MaxInt64) {
			return nil
		}
		return int64(value)
	case *float64:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	case string:
		val, err := strconv.ParseFloat(value, 0)
		if err != nil {
			return nil
		}
		return coerceAnyInt(val)
	case *string:
		if value == nil {
			return nil
		}
		return coerceAnyInt(*value)
	}

	return nil
}

var Int32 = graphql.NewScalar(graphql.ScalarConfig{
	Name: "Int32",
	Description: "The `Int32` scalar type represents non-fractional signed whole numeric " +
		"values. Int can represent values between -(2^31) and 2^31 - 1. ",
	Serialize:  coerceAnyInt,
	ParseValue: coerceAnyInt,
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.IntValue:
			if int32Value, err := strconv.ParseInt(valueAST.Value, 10, 32); err == nil {
				return int32Value
			}
		}
		return nil
	},
})

var Int64 = graphql.NewScalar(graphql.ScalarConfig{
	Name: "Int64",
	Description: "The `Int64` scalar type represents non-fractional signed whole numeric " +
		"values. Int can represent values between -(2^63) and 2^63 - 1. ",
	Serialize:  coerceAnyInt,
	ParseValue: coerceAnyInt,
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.IntValue:
			if int64Value, err := strconv.ParseInt(valueAST.Value, 10, 64); err == nil {
				return int64Value
			}
		}
		return nil
	},
})

var UInt32 = graphql.NewScalar(graphql.ScalarConfig{
	Name: "UInt32",
	Description: "The `UInt32` scalar type represents non-fractional signed whole numeric " +
		"values. Int can represent values between 0 and 2^63 - 1. ",
	Serialize:  coerceAnyInt,
	ParseValue: coerceAnyInt,
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.IntValue:
			if uint32Value, err := strconv.ParseUint(valueAST.Value, 10, 32); err == nil {
				return uint32Value
			}
		}
		return nil
	},
})

var UInt64 = graphql.NewScalar(graphql.ScalarConfig{
	Name: "UInt64",
	Description: "The `UInt64` scalar type represents non-fractional signed whole numeric " +
		"values. Int can represent values between 0 and 2^127 - 1. ",
	Serialize:  coerceAnyInt,
	ParseValue: coerceAnyInt,
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.IntValue:
			if uint64Value, err := strconv.ParseUint(valueAST.Value, 10, 64); err == nil {
				return uint64Value
			}
		}
		return nil
	},
})
