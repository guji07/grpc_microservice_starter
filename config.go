package grpc_microservice_starter

type Config struct {
	HttpBind    string `env:"SERVER_HTTP_BIND" envDefault:":9000"`
	MetricsBind string `env:"SERVER_METRICS_BIND" envDefault:":9090"`
	ProbeBind   string `env:"SERVER_PROBE_BIND" envDefault:":8091"`
	GrpcBind    string `env:"SERVER_GRPC_BIND" envDefault:":8093"`
	ServiceName string `env:"SERVICE_NAME,required"`
	JaegerUrl   string `env:"JAEGER_URL" envDefault:"http://jaeger-collector.tracing.svc:14268/api/traces"`
}
