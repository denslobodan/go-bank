package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	store "github.com/denslobodan/go-bank/internal/storage"
	pkg "github.com/denslobodan/go-bank/pkg/types"
)

type APIServer struct {
	listenAddr string
	store      store.Storage
}

// NewAPIServer creates a new instance of APIServer.
func NewAPIServer(listenAddr string, store store.Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

// Run starts the API server.
func (s *APIServer) Run() {
	router := mux.NewRouter()

	loggedRouter := handlers.LoggingHandler(os.Stdout, router)

	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id:[0-9]+}", withJWTAuth(makeHTTPHandleFunc(s.handleGetAccountByID), s.store))
	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	log.Println("APIServer running on ", fmt.Sprintf("port: %s", s.listenAddr))

	http.ListenAndServe(s.listenAddr, loggedRouter)
}

// handleLogin handles the login request.
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		err := WriteJSON(w, http.StatusMethodNotAllowed, nil)
		if err != nil {
			return err
		}
		return fmt.Errorf("method not allowed")
	}

	var req pkg.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc, err := s.store.GetAccountByNumber(int64(req.Number))
	if err != nil {
		return err
	}

	if acc.ValidPassword(req.Password) {
		return WriteJSON(w, http.StatusForbidden, nil)
	}

	token, err := createJWT(acc)
	if err != nil {
		return err
	}

	resp := pkg.LoginResponse{
		Token:  token,
		Number: acc.Number,
	}

	return WriteJSON(w, http.StatusOK, resp)
}

// handleAccount handles requests related to accounts.
func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}

	if err := WriteJSON(w, http.StatusMethodNotAllowed, nil); err != nil {
		return err
	}

	return fmt.Errorf("method not allowed")
}

// handleGetAccount handles the request to get accounts
func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, accounts)
}

// handleGetAccountByID handles the request to get an account by ID.
func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		id, err := getID(r)
		if err != nil {
			return err
		}
		account, err := s.store.GetAccountByID(id)
		if err != nil {
			if err := WriteJSON(w, http.StatusNotFound, err); err != nil {
				return err
			}
			return fmt.Errorf("account not found")
		}

		return WriteJSON(w, http.StatusOK, account)
	}

	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}

	if err := WriteJSON(w, http.StatusMethodNotAllowed, nil); err != nil {
		return err
	}

	return fmt.Errorf("method not allowed")
}

// handleCreateAccount handles the request to create an account.
func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(pkg.CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	account, err := pkg.NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		err = WriteJSON(w, http.StatusBadRequest, nil)
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid account")
	}
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

// handleDeleteAccount handles the request to delete an account by ID.
func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

// handleTransfer handles the transfer request.
func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferReq := new(pkg.TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}
	defer r.Body.Close()

	if transferReq.ToAccount <= 0 {
		err := WriteJSON(w, http.StatusBadRequest, nil)
		if err != nil {
			return err
		}

		return fmt.Errorf("error transfer")
	}

	return WriteJSON(w, http.StatusOK, transferReq)
}

// WriteJSON writes JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(v)
}

// createJWT creates a JWT token for the account.
func createJWT(account *pkg.Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt":     15000,
		"accountNumber": account.Number,
	}

	secret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

// permissionDenied handles permission denied response.
func permissionDenied(w http.ResponseWriter) {
	if err := WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"}); err != nil {
		log.Fatalf(err.Error())
	}
}

// withJWTAuth is a JWT authentication middleware.
func withJWTAuth(handlerFunc http.HandlerFunc, s store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("calling JWT auth middleware")

		tokenString := r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)
		if err != nil {
			permissionDenied(w)
			return
		}

		if !token.Valid {
			permissionDenied(w)
			return
		}

		userID, err := getID(r)
		if err != nil {
			permissionDenied(w)
			return
		}
		account, err := s.GetAccountByID(userID)
		if err != nil {
			permissionDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		if account.Number != int64(claims["accountNumber"].(float64)) {
			permissionDenied(w)
		}

		if err != nil {
			if err := WriteJSON(w, http.StatusForbidden, nil); err != nil {
				return
			}
		}

		handlerFunc(w, r)
	}
}

// validateJWT validates the JWT token.
func validateJWT(tokenString string) (*jwt.Token, error) {

	secret := os.Getenv("JWT_SECRET")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// string([]byte(secret))

		return []byte(secret), nil
	})
}

type apiFunc func(http.ResponseWriter, *http.Request) error

// ApiError represents an API error response.
type ApiError struct {
	Error string `json:"error"`
}

// makeHTTPHandleFunc creates an HTTP handler function from an API function.
func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			err = WriteJSON(w, http.StatusBadRequest, nil)
			if err != nil {
				return
			}
		}
	}
}

// getID extracts the ID from the request.
func getID(r *http.Request) (int, error) {
	// idStr := mux.Vars(r)["id"]
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invaild id given %s", idStr)
	}

	return id, nil
}
