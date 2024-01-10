package keycloak

type Config struct {
	IsEnabled    bool   `env:"ENABLED"`
	Host         string `env:"HOST"`          // Хост KeyCloak, на данный момент "keycloak.wildberries.ru"
	ClientID     string `env:"CLIENT_ID"`     // ClientID в KeyCloak, в нашем случае "authorized-services-admin"
	ClientSecret string `env:"CLIENT_SECRET"` // Выдаётся после регистрации сервиса в KeyCloak, хранится в vault
	Realm        string `env:"REALM"`         // Выдаётся после регистрации сервиса в KeyCloak, обычно "infrastructure"
	BackURL      string `env:"BACK_URL"`      // URL сервиса, на который надо отредиректить пользователя после успешного логина в KeyCloak и записи токена в куку
	RedisURL     string `env:"REDIS_URL"`     // URL сервиса, на который надо отредиректить пользователя после успешного логина в KeyCloak и записи токена в куку
}
