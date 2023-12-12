package main

import (
	"github.com/BerryTracer/auth-service/grpc/server"
	"github.com/BerryTracer/auth-service/service"
	"github.com/BerryTracer/common-service/crypto"
	userservice "github.com/BerryTracer/user-service/grpc/proto"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Connect to gRPC server
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalln(err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Fatalln(err)
		}
	}(conn)

	// Create services
	userServiceClient := userservice.NewUserServiceClient(conn)
	tokenService := service.NewTokenService("secret")
	passwordHasher := crypto.NewBcryptHasher()
	authService := service.NewAuthServiceImpl(userServiceClient, tokenService, passwordHasher)

	// Run gRPC server
	err = server.NewAuthGRPCServer(authService).Run(":50052")
	if err != nil {
		log.Fatalln(err)
	}
}
