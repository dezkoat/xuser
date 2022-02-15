package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50002, "Server port")
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	} else {
		log.Printf("Listening to port %v", *port)
	}

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	grpcServer.Serve(lis)
}
