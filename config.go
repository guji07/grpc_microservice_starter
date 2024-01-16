package grpc_microservice_starter

import "github.com/guji07/grpc_microservice_starter/interceptors/keycloak"

type Config struct {
	//structs
	Server      ServerConfig      `envPrefix:"SERVER_"`
	Interceptor InterceptorConfig `envPrefix:"INTERCEPTOR_"`
	Keycloak    keycloak.Config   `envPrefix:"KEYCLOAK_"`
	//non-group config values
	ServiceName string `env:"SERVICE_NAME,required"`
	JaegerUrl   string `env:"JAEGER_URL" envDefault:"http://jaeger-collector.tracing.svc:14268/api/traces"`
}

type ServerConfig struct {
	HttpBind    string `env:"HTTP_BIND" envDefault:":9000"`
	MetricsBind string `env:"METRICS_BIND" envDefault:":9090"`
	ProbeBind   string `env:"PROBE_BIND" envDefault:":8091"`
	GrpcBind    string `env:"GRPC_BIND" envDefault:":8093"`
}

type InterceptorConfig struct {
	EnableMetricsInterceptor    bool   `env:"METRICS_ENABLED"`
	EnableValidationInterceptor bool   `env:"VALIDATION_ENABLED"`
	EnableKeycloakInterceptor   bool   `env:"KEYCLOAK_ENABLED"`
	EscapePrefix                string `env:"KEYCLOAK_ESCAPE_PREFIX" envDefault:"/srv"`
}
