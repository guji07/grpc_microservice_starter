package storage

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"sync"
	"time"
)

func NewRedisStorage(ctx context.Context, redisURL string) (*RedisStorage, error) {
	client, err := NewRedisClient(ctx, redisURL)
	if err != nil {
		return nil, err
	}

	s := RedisStorage{
		client: client,
	}

	return &s, nil
}

type RedisStorage struct {
	client       *redis.Client
	storageMutex sync.RWMutex
}

func (s *RedisStorage) Get(ctx context.Context, uuid string) (string, bool) {
	res := s.client.Get(ctx, uuid)
	if !errors.Is(res.Err(), redis.Nil) {
		return res.Val(), true
	}

	return "", false
}

func (s *RedisStorage) Set(ctx context.Context, uuid, token string, expiration int) {
	s.client.Set(ctx, uuid, token, time.Duration(expiration)*time.Second)
}
