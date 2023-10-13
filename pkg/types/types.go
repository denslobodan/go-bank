package types

import (
	"errors"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	errFName error = errors.New("invalid characters in firstName")
	errLName error = errors.New("invalid characters in lastName")
)

type LoginResponse struct {
	Number int64  `json:"number"`
	Token  string `json:"token"`
}

type LoginRequest struct {
	Number   int64  `json:"number"`
	Password string `json:"password"`
}

type TransferRequest struct {
	ToAccount int `json:"toAccount"`
	Amount    int `json:"Amount"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type Account struct {
	ID                int       `json:"id"`
	FirstName         string    `json:"firstName"`
	LastName          string    `json:"lastName"`
	Number            int64     `json:"number"`
	EncryptedPassword string    `json:"-"`
	Balance           int64     `json:"balance"`
	CreatedAt         time.Time `json:"createdAt" testify:"omitempty"` //omitempty
}

func (a *Account) ValidPassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pw)) != nil
}

func NewAccount(firstName, lastName, password string) (*Account, error) {
	if !vallidateName(firstName) {
		return nil, errFName
	}

	if !vallidateName(lastName) {
		return nil, errLName
	}

	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Account{
		FirstName:         firstName,
		LastName:          lastName,
		Number:            int64(rand.Intn(1000000)),
		EncryptedPassword: string(encpw),
		CreatedAt:         time.Now().UTC(),
	}, nil
}

func vallidateName(name string) bool {
	name = strings.TrimSpace(name)

	if name == "" {
		return false
	}

	// Проверка корректности name с помощью регулярного выражения
	nameRegex := regexp.MustCompile(`^[A-Za-z]+$`)

	return nameRegex.MatchString(name)
}
