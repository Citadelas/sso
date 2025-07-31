package app

import (
	grpcapp "github.com/muerewa/sso/internal/app/grpc"
	"github.com/muerewa/sso/internal/services/auth"
	"github.com/muerewa/sso/internal/storage/postgresql"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL, refTokenTTL time.Duration) *App {
	storage, err := postgresql.New(storagePath)
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, storage, storage, storage, tokenTTL, refTokenTTL)
	grpcApp := grpcapp.New(log, authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}
