package storage

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

func NewRedisClient(ctx context.Context, redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	opts.DialTimeout = time.Second
	opts.ReadTimeout = time.Millisecond * 50
	opts.WriteTimeout = time.Millisecond * 50

	client := redis.NewClient(opts)
	for i := 0; i < 5; i++ {
		if err != nil {
			time.Sleep(time.Second)
		}
		_, err = client.Ping(ctx).Result()
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}

	return client, nil
}
