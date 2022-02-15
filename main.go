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
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/dezkoat/xuser/proto"
)

var (
	port           = flag.Int("port", 50002, "Server port")
	privateKeyPath = flag.String("key", "./key/private.pem", "Private Key File Path")
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
			ExpiresAt: time.Now().Add(time.Minute * 60).Unix(),
		},
		"dean@gmail.com",
	}

	tokenString, err := t.SignedString(s.PrivateKey)
	log.Printf(tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &s.PrivateKey.PublicKey, nil
	})

	if err != nil {
		log.Printf("ERROR!!! %v", err)
	}

	claims := token.Claims.(*UserClaims)
	log.Printf("[%v]", claims)

	return nil, nil
}

func (s *UserServer) GetUserPublicKey(ctx context.Context, e *emptypb.Empty) (*pb.UserPublicKey, error) {
	if s.PrivateKey == nil {
		return nil, errors.New("Key not initialized")
	}

	return &pb.UserPublicKey{
		Modulus:  s.PrivateKey.PublicKey.N.String(),
		Exponent: int64(s.PrivateKey.PublicKey.E),
	}, nil
}

type UserClaims struct {
	*jwt.StandardClaims
	Email string
}

func readKey() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(*privateKeyPath)
	if err != nil {
		log.Fatalf("Error reading file %v: %v", privateKeyPath, err)
	}

	privPem, _ := pem.Decode(priv)
	return x509.ParsePKCS1PrivateKey(privPem.Bytes)
}

func initUserMap() map[string]string {
	userMap := make(map[string]string)
	for _, user := range userList {
		userMap[user.Username] = user.Password
	}

	return userMap
}

func main() {
	key, err := readKey()
	if err != nil {
		log.Fatalf("Error reading key %v", err)
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
			UserMap:    initUserMap(),
		},
	)
	grpcServer.Serve(listener)
}
