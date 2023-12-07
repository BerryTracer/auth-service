package server

import (
	"context"
	"log"
	"net"

	pb "github.com/BerryTracer/auth-service/grpc/proto"
	"github.com/BerryTracer/auth-service/service"
	"google.golang.org/grpc"
)

type AuthGRPCServer struct {
	pb.UnimplementedAuthServiceServer
	AuthService service.AuthService
}

// NewAuthGRPCServer creates a new gRPC server.
func NewAuthGRPCServer(authService service.AuthService) *AuthGRPCServer {
	return &AuthGRPCServer{
		AuthService: authService,
	}
}

// Run starts the gRPC server.
func (s *AuthGRPCServer) Run(port string) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
		return err
	}
	server := grpc.NewServer()
	pb.RegisterAuthServiceServer(server, s)
	log.Printf("Auth gRPC server listening on port %s\n", port)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v\n", err)
		return err
	}
	return nil
}

// SignUp implements AuthServiceServer.
func (s *AuthGRPCServer) SignUp(ctx context.Context, req *pb.SignUpRequest) (*pb.Token, error) {
	token, err := s.AuthService.SignUp(ctx, req.Email, req.Username, req.Password)

	if err != nil {
		return nil, err
	}

	return &pb.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

// SignIn implements AuthServiceServer.
func (s *AuthGRPCServer) SignIn(ctx context.Context, req *pb.SignInRequest) (*pb.Token, error) {
	token, err := s.AuthService.SignIn(ctx, req.Email, req.Password)

	if err != nil {
		return nil, err
	}

	return &pb.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

// VerifyToken implements AuthServiceServer.
func (s *AuthGRPCServer) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	isValid, claims, err := s.AuthService.VerifyToken(ctx, req.Token)

	if err != nil {
		return nil, err
	}

	// Convert claims to map[string]string
	stringClaims := make(map[string]string)
	for key, value := range claims {
		stringClaims[key] = value.(string)
	}

	return &pb.VerifyTokenResponse{
		Valid:  isValid,
		Claims: stringClaims,
	}, nil
}

// RefreshToken implements AuthServiceServer.
func (s *AuthGRPCServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.Token, error) {
	token, err := s.AuthService.RefreshToken(ctx, req.Token)

	if err != nil {
		return nil, err
	}

	return &pb.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}
