package keycloak

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type ParsedToken struct {
	Claims    *jwt.MapClaims
	UserEmail string
	UserName  string
	UUID      string
}

// parseToken parses the given token in a gRPC context.
func (s *Service) parseToken(ctx context.Context, token string) (*ParsedToken, error) {
	accessToken, claims, err := s.DecodeAccessToken(ctx, token) // Assuming DecodeAccessToken is adapted for gRPC
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !accessToken.Valid {
		return nil, errors.Errorf("token is not valid: %v", token)
	}

	email, ok := (*claims)["email"].(string)
	if !ok {
		return nil, errors.Errorf("token claims do not contain an email: %v", *claims)
	}

	firstname, ok := (*claims)["given_name"].(string)
	if !ok {
		return nil, errors.Errorf("token claims do not contain a given_name: %v", *claims)
	}
	surname, ok := (*claims)["family_name"].(string)
	if !ok {
		return nil, errors.Errorf("token claims do not contain a family_name: %v", *claims)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	t := ParsedToken{
		UUID:      fmt.Sprintf("%s_%s_%s", CookieName_UUID, email, id.String()),
		Claims:    claims,
		UserEmail: email,
		UserName:  fmt.Sprintf("%s %s", firstname, surname),
	}

	return &t, nil
}
