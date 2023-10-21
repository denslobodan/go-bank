package types

import (
	"testing"
)

// Creates a new account with valid first name, last name, and password
func TestCreateNewAccountWithValidDetails(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	password := "password123"

	account, err := NewAccount(firstName, lastName, password)

	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if account.FirstName != firstName {
		t.Errorf("Expected first name to be %s, but got %s", firstName, account.FirstName)
	}

	if account.LastName != lastName {
		t.Errorf("Expected last name to be %s, but got %s", lastName, account.LastName)
	}

	if account.Number == 0 {
		t.Errorf("Expected account number to be non-zero")
	}

	if account.EncryptedPassword == "" {
		t.Errorf("Expected encrypted password to be non-empty")
	}
}

// Generates a random number for the new account
func TestGenerateRandomNumber(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	password := "password123"

	account, err := NewAccount(firstName, lastName, password)

	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if account.Number == 0 {
		t.Errorf("Expected account number to be non-zero")
	}
}

// Encrypts the password for the new account
func TestEncryptPassword(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	password := "password123"

	account, err := NewAccount(firstName, lastName, password)

	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	if account.EncryptedPassword == "" {
		t.Errorf("Expected encrypted password to be non-empty")
	}
}

// Returns an error if the first name is empty
func TestReturnErrorIfFirstNameEmpty(t *testing.T) {
	firstName := ""
	lastName := "Doe"
	password := "password123"

	account, err := NewAccount(firstName, lastName, password)

	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}

	if account != nil {
		t.Errorf("Expected account to be nil, but got %v", account)
	}
}

// Returns an error if the last name is empty
func TestReturnErrorIfLastNameEmpty(t *testing.T) {
	firstName := "John"
	lastName := ""
	password := "password123"

	account, err := NewAccount(firstName, lastName, password)

	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}

	if account != nil {
		t.Errorf("Expected account to be nil, but got %v", account)
	}
}

// Returns an error if the password is empty
func TestReturnErrorIfPasswordEmpty(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	password := ""

	account, err := NewAccount(firstName, lastName, password)

	if err != nil {
		t.Errorf("Expected an error, but got nil")
	}

	if account == nil {
		t.Errorf("Expected account to be nil, but got %v", account)
	}
}
