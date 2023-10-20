package store

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	types "github.com/denslobodan/go-bank/pkg/types"
)

type Storage interface {
	CreateAccount(*types.Account) error
	DeleteAccount(int) error
	UpdateAccount(*types.Account) error
	GetAccounts() ([]*types.Account, error)
	GetAccountByID(int) (*types.Account, error)
	GetAccountByNumber(int64) (*types.Account, error)
}

type PostgresStore struct {
	DB *sql.DB
}

// NewPostgresStore creates a new instance of PostgresStore.
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("соединение отсутствует: %v", err)
	}

	return &PostgresStore{
		DB: db,
	}, nil
}

// Init initializes the PostgresStore.
func (s PostgresStore) Init() error {
	return s.createAccountTable()
}

// createAccountTable creates the "account" table if it doesn't exist.
func (s *PostgresStore) createAccountTable() error {
	query := `create table if not exists account (
		id serial primary key,
		first_name varchar(100),
		last_name varchar(100),
		number serial,
		encrypted_password varchar(100),
		balance serial,
		created_at timestamp)`

	_, err := s.DB.Exec(query)
	return err
}

// CreateAccount creates a new account.
func (s *PostgresStore) CreateAccount(acc *types.Account) error {
	query := `insert into account
		(first_name, last_name, number, encrypted_password, balance, created_at)
		values ($1, $2, $3, $4, $5, $6)`

	_, err := s.DB.Query(
		query,
		acc.FirstName,
		acc.LastName,
		acc.Number,
		acc.EncryptedPassword,
		acc.Balance,
		acc.CreatedAt,
	)

	if err != nil {
		return err
	}

	return nil
}

// UpdateAccount updates an existing account.
func (s *PostgresStore) UpdateAccount(account *types.Account) error {
	query := `UPDATE account SET first_name = $1, last_name = $2, balance = $3 WHERE id = $4`

	_, err := s.DB.Exec(query, account.FirstName, account.LastName, account.Balance, account.ID)
	if err != nil {
		return err
	}

	return nil
}

// DeleteAccount deletes an account by ID.
func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.DB.Query("delete from account where id = $1", id)
	return err
}

// GetAccountByNumber retrieves an account by its number.
func (s *PostgresStore) GetAccountByNumber(number int64) (*types.Account, error) {
	rows, err := s.DB.Query("select * from account where number = $1", number)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account with number [%d] not found", number)
}

// GetAccountByID retrieves an account by its ID.
func (s *PostgresStore) GetAccountByID(id int) (*types.Account, error) {
	rows, err := s.DB.Query("select * from account where id = $1", id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account %d not found", id)
}

// GetAccounts retrieves a list of all accounts.
func (s *PostgresStore) GetAccounts() ([]*types.Account, error) {
	rows, err := s.DB.Query("select * from account")
	if err != nil {
		return nil, err
	}

	accounts := []*types.Account{}
	for rows.Next() {
		account, err := scanIntoAccount(rows)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}
	return accounts, nil
}

// scanIntoAccount scans a row into an Account struct.
func scanIntoAccount(rows *sql.Rows) (*types.Account, error) {
	account := new(types.Account)
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Number,
		&account.EncryptedPassword,
		&account.Balance,
		&account.CreatedAt)

	return account, err
}
