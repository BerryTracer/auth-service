package main

import (
	"github.com/BerryTracer/auth-service/grpc/server"
	"github.com/BerryTracer/auth-service/service"
	"github.com/BerryTracer/common-service/crypto"
	user_service "github.com/BerryTracer/user-service/grpc/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	userServiceClient := user_service.NewUserServiceClient(conn)
	tokenService := service.NewTokenService("secret")
	passwordHasher := crypto.NewBcryptHasher()

	authService := service.NewAuthServiceImpl(userServiceClient, tokenService, passwordHasher)

	server.NewAuthGRPCServer(authService).Run(":50052")
}
