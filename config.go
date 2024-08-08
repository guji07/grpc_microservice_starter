package grpc_microservice_starter

type Config struct {
	//structs
	Server      ServerConfig      `envPrefix:"SERVER_"`
	Interceptor InterceptorConfig `envPrefix:"INTERCEPTOR_"`
	IAM         IAMConfig         `envPrefix:"IAM_"`
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
	EnableMetricsInterceptor    bool   `env:"METRICS_ENABLED" envDefault:"true"`
	EnableValidationInterceptor bool   `env:"VALIDATION_ENABLED" envDefault:"true"`
	EnableKeycloakInterceptor   bool   `env:"KEYCLOAK_ENABLED" envDefault:"false"`
	EnableIAMInterceptor        bool   `env:"IAM_ENABLED" envDefault:"false"`
	EscapePrefix                string `env:"KEYCLOAK_ESCAPE_PREFIX" envDefault:"/srv"`
}

type IAMConfig struct {
	IAMHost   string `env:"HOST"`
	ServiceId string `env:"SERVICE_ID"`
}
