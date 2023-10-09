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
	DeleteAllAccounts() error
	UpdateAccount(*types.Account) error
	GetAccounts() ([]*types.Account, error)
	GetAccountByID(int) (*types.Account, error)
	GetAccountByNumber(int64) (*types.Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(connStr string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `create table if not exists account (
		id serial primary key,
		first_name varchar(100),
		last_name varchar(100),
		number serial,
		encrypted_password varchar(100),
		balance serial,
		created_at timestamp)`

	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) CreateAccount(acc *types.Account) error {
	query := `insert into account 
		(first_name, last_name, number, encrypted_password, balance, created_at)
		values ($1, $2, $3, $4, $5, $6)`

	_, err := s.db.Query(
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
func (s *PostgresStore) UpdateAccount(account *types.Account) error {
	query := `UPDATE account SET first_name = $1, last_name = $2, balance = $3 WHERE id = $4`

	_, err := s.db.Exec(query, account.FirstName, account.LastName, account.Balance, account.ID)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("delete from account where id = $1", id)
	return err
}

func (s *PostgresStore) GetAccountByNumber(number int64) (*types.Account, error) {
	rows, err := s.db.Query("select * from account where number = $1", number)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account with number [%d] not found", number)
}

func (s *PostgresStore) GetAccountByID(id int) (*types.Account, error) {
	rows, err := s.db.Query("select * from account where id = $1", id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return scanIntoAccount(rows)
	}
	return nil, fmt.Errorf("account %d not found", id)
}

func (s *PostgresStore) GetAccounts() ([]*types.Account, error) {
	rows, err := s.db.Query("select * from account")
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

func (s *PostgresStore) DeleteAllAccounts() error {
	// Подготовка SQL-запроса для удаления всех записей из таблицы accounts
	query := `DELETE FROM account;`

	// Выполнение SQL-запроса
	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}
