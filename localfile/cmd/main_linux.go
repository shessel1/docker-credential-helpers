package main

import (
	"log"
	"os"

	"path/filepath"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/localfile"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(dir, "docker-credentials.json")
	file, err := localfile.NewLocalFile(path)
	if err != nil {
		log.Fatal(err)
	}
	credentials.Serve(file)
}
