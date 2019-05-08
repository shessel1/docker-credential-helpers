package localfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/docker/docker-credential-helpers/credentials"
	"golang.org/x/crypto/scrypt"
)

const (
	secretEnvName    = "DOCKER_CREDENTIAL_FILE_SECRET"
	noSecretErrorMsg = `No secret provided. Please set "` + secretEnvName + `"`
	notFoundErrorMsg = `No credentials found for "%s"`
)

type LocalFile struct {
	Path        string
	Secret      *[]byte
	Credentials map[string]Credentials
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
}

func NewLocalFile(path string) (*LocalFile, error) {
	secretenv, ok := os.LookupEnv(secretEnvName)
	if !ok {
		return nil, errors.New(noSecretErrorMsg)
	}
	secret := []byte(secretenv)
	file := &LocalFile{path, &secret, make(map[string]Credentials)}
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := file.WriteFile(); err != nil {
			return nil, err
		}
	}
	return file, nil
}

func (f *LocalFile) Add(cred *credentials.Credentials) error {
	if err := f.ReadFile(); err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key, err := scrypt.Key(*f.Secret, salt, 32768, 8, 1, 32)
	password, err := f.Encrypt(cred.Secret, &key)
	if err != nil {
		return err
	}
	f.Credentials[cred.ServerURL] = Credentials{cred.Username, password, hex.EncodeToString(salt)}
	return f.WriteFile()
}

func (f *LocalFile) Delete(url string) error {
	if err := f.ReadFile(); err != nil {
		return err
	}
	delete(f.Credentials, url)
	return f.WriteFile()
}

func (f *LocalFile) List() (map[string]string, error) {
	if err := f.ReadFile(); err != nil {
		return nil, err
	}
	creds := make(map[string]string)
	for url, cred := range f.Credentials {
		creds[url] = cred.Username
	}
	return creds, nil
}

func (f *LocalFile) Get(url string) (string, string, error) {
	if err := f.ReadFile(); err != nil {
		return "", "", err
	}
	cred, ok := f.Credentials[url]
	if !ok {
		return "", "", fmt.Errorf(notFoundErrorMsg, url)
	}
	salt, err := hex.DecodeString(cred.Salt)
	if err != nil {
		return "", "", err
	}
	key, err := scrypt.Key(*f.Secret, salt, 32768, 8, 1, 32)
	password, err := f.Decrypt(cred.Password, &key)
	if err != nil {
		return "", "", err
	}
	return cred.Username, password, nil
}

func (f *LocalFile) ReadFile() error {
	bytes, err := ioutil.ReadFile(f.Path)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, &f.Credentials)
}

func (f *LocalFile) WriteFile() error {
	json, err := json.Marshal(&f.Credentials)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f.Path, json, 0644)
}

func (f *LocalFile) Encrypt(s string, key *[]byte) (string, error) {
	block, err := aes.NewCipher(*key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	data := gcm.Seal(nil, nonce, []byte(s), nil)
	return hex.EncodeToString(append(nonce, data...)), nil
}

func (f *LocalFile) Decrypt(s string, key *[]byte) (string, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(*key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
