package grpc_microservice_starter

import (
	"time"
)

type ServerOptionsConfig struct {
	HttpBind         string        `env:"SERVER_HTTP_BIND" envDefault:":9000"`
	MetricsBind      string        `env:"SERVER_METRICS_BIND" envDefault:":9090"`
	ProbeBind        string        `env:"SERVER_PROBE_BIND" envDefault:":8091"`
	GrpcBind         string        `env:"SERVER_GRPC_BIND" envDefault:":8093"`
	ReadTimeout      time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"40s"`
	WriteTimeout     time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"40s"`
	IdleTimeout      time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"40s"`
	ServiceName      string        `env:"SERVICE_NAME" envDefault:"templates-api"`
	ServiceNamespace string        `env:"SERVICE_NAMESPACE" envDefault:"sapient_bot"`
	JaegerUrl        string        `env:"JAEGER_URL,required"`
}
