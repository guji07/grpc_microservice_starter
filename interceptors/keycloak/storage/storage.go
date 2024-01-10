package storage

import "context"

type TokenStorage interface {
	Get(ctx context.Context, uuid string) (string, bool)
	Set(ctx context.Context, uuid, token string, expiration int)
}
