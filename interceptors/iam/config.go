package iam

type IAMConfig struct {
	IAMHost   string `env:"HOST"`
	ServiceId string `env:"SERVICE_ID"`
}
