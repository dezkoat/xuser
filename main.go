package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc"

	pb "github.com/dezkoat/xuser/proto"
)

var (
	port           = flag.Int("port", 50002, "Server port")
	privateKeyPath = flag.String("key", "./key/private.pem", "Private Key File Path used in User Credentials Authentication")
)

type UserInfo struct {
	Username string
	Password string
}

var userList = []UserInfo{
	{
		Username: "admin",
		Password: "admin1234",
	},
	{
		Username: "dezkoat",
		Password: "dezkoat1234",
	},
}

type UserServer struct {
	pb.UnimplementedUserServer
	*rsa.PrivateKey
	UserMap map[string]string
}

func (s *UserServer) Login(ctx context.Context, req *pb.UserInfo) (*pb.UserToken, error) {
	if _, ok := s.UserMap[req.Username]; !ok {
		return nil, errors.New("Wrong credentials")
	}

	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &UserClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 60).Unix(),
		},
		req.Username,
	}

	tokenString, err := t.SignedString(s.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &pb.UserToken{
		Token: tokenString,
	}, nil
}

type UserClaims struct {
	*jwt.StandardClaims
	Email string
}

func ReadPrivateKey() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(*privateKeyPath)
	if err != nil {
		log.Fatalf("Error reading file %v: %v", privateKeyPath, err)
	}

	privPem, _ := pem.Decode(priv)
	return x509.ParsePKCS1PrivateKey(privPem.Bytes)
}

func InitUserMap() map[string]string {
	userMap := make(map[string]string)
	for _, user := range userList {
		userMap[user.Username] = user.Password
	}

	return userMap
}

func main() {
	key, err := ReadPrivateKey()
	if err != nil {
		log.Fatalf("Error reading private key %v", err)
	}

	flag.Parse()
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	} else {
		log.Printf("Listening to port %v", *port)
	}

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterUserServer(
		grpcServer,
		&UserServer{
			PrivateKey: key,
			UserMap:    InitUserMap(),
		},
	)
	grpcServer.Serve(listener)
}
