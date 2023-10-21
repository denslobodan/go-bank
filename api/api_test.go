package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	mock_store "github.com/denslobodan/go-bank/pkg/mocks"
	pkg "github.com/denslobodan/go-bank/pkg/types"
	"github.com/golang-jwt/jwt"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestAPIServerRun(t *testing.T) {
	tt := []struct {
		name          string
		path          string
		method        string
		request       pkg.LoginRequest
		routeVariable string
	}{
		{
			name:   "Login endpoint handleLogin",
			path:   "/login",
			method: "POST",
			request: pkg.LoginRequest{
				Number:   123456789,
				Password: "password",
			},
		},
		{
			name:    "Account endpoint handleAccount",
			path:    "/account",
			method:  "GET",
			request: pkg.LoginRequest{},
		},
		{
			name:    "Account endpoint handleGetAccountByID",
			path:    "/account/1",
			method:  "GET",
			request: pkg.LoginRequest{},
		},
		{
			name:    "Account endpoint handleDeleteAccount",
			path:    "/account/1",
			method:  "POST",
			request: pkg.LoginRequest{},
		},
		{
			name:    "Account endpoint hanldeTransfer",
			path:    "/transfer",
			method:  "POST",
			request: pkg.LoginRequest{},
		},
	}

	for _, tc := range tt {
		server := APIServer{}

		jsonReq, _ := json.Marshal(tc.request)

		_, err := http.NewRequest(tc.method, tc.path, bytes.NewBuffer(jsonReq))
		if err != nil {
			t.Error(err)
		}

		rr := httptest.NewRecorder()

		// Need to create a router that we can pass the request through so that the vars will be added to the context
		server.Run()

		// Check the response status code
		assert.Equal(t, rr.Code, http.StatusOK)
	}
}

func TestAPIServer_handleLogin(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name     string
		number   int64
		password string
		token    string
		method   string
		status   int
		wantErr  bool
		err      error
	}{
		{
			name:     "Valid logining",
			password: "password",
			number:   123456789,
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjoxMjM0NTY3ODksImV4cGlyZXNBdCI6MTUwMDB9.rW9nEbnMqzZaoAiiAeO05lRorih0drS6z_mNwr0GaCE",
			method:   "POST",
			status:   http.StatusOK,
			wantErr:  false,
			err:      nil,
		},
		{
			name:    "Invalid method logining",
			number:  123456789,
			method:  "PATCH",
			status:  http.StatusMethodNotAllowed,
			wantErr: true,
			err:     fmt.Errorf("method not allowed PATCH"),
		},
		{
			name:     "Invalid password logining",
			number:   123456789,
			password: "query",
			method:   "POST",
			status:   http.StatusForbidden,
			wantErr:  true,
			err:      fmt.Errorf("not authenticated"),
		},
		{
			name:     "Invalid number logining",
			number:   0,
			password: "password",
			method:   "POST",
			status:   http.StatusForbidden,
			wantErr:  true,
			err:      fmt.Errorf("not authenticated"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock storage
			storage := createMockStorage(t)

			// Create a new instance of APIServer with the mock store
			server := NewAPIServer("localhost:8080", storage)

			account := &pkg.Account{
				ID:                1,
				FirstName:         "Bob",
				LastName:          "Ross",
				EncryptedPassword: "$2a$10$pyyAbptYdjOSfj/ZoX0T2OmM81UcdvnyTdDHDa37PiQHp/VLTpQie",
				Number:            123456789,
				Balance:           100,
				CreatedAt:         time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
			}

			if tc.wantErr {
				account = nil
			}

			loginRequest := &pkg.LoginRequest{
				Number:   tc.number,
				Password: tc.password,
			}
			loginResponse := &pkg.LoginResponse{
				Number: tc.number,
				Token:  tc.token,
			}

			// Convert the request body to JSON
			jsonReq, _ := json.Marshal(loginRequest)

			req, _ := http.NewRequest(tc.method, "/login", bytes.NewBuffer(jsonReq))

			rr := httptest.NewRecorder()

			storage.EXPECT().GetAccountByNumber(loginRequest.Number).Return(account, tc.err)

			err := server.handleLogin(rr, req)

			if tc.wantErr {
				assert.Error(t, err)

				return
			}

			if err != nil {
				assert.ErrorAs(t, err, tc.err)
			}

			var resp pkg.LoginResponse

			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Error(err)
			}

			assert.Equal(t, loginResponse, &resp)

			assert.NoError(t, err)

			// Check the response status code
			assert.Equal(t, tc.status, rr.Code)
		})
	}

}

func TestAPIServer_handleTransfer(t *testing.T) {
	// Create mockStorage
	storage := createMockStorage(t)

	// Create a new instance of APIServer with the mock store
	server := NewAPIServer("localhost:8080", storage)

	testCases := []struct {
		name           string
		transferReq    pkg.TransferRequest
		expectedStatus int
		wantErr        bool
	}{
		{
			name: "Successful transfer",
			transferReq: pkg.TransferRequest{
				ToAccount: 1000,
				Amount:    100,
			},
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "Error transfer",
			transferReq: pkg.TransferRequest{
				ToAccount: 0, // Invalid account number
				Amount:    0,
			},
			expectedStatus: http.StatusBadRequest,
			wantErr:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonReq, _ := json.Marshal(tc.transferReq)

			jsonReq = convertToBytes(string(jsonReq))

			req, _ := http.NewRequest("POST", "/transfer", bytes.NewBuffer(jsonReq))

			recorder := httptest.NewRecorder()

			// Call the handle method with the recorder and request
			err := server.handleTransfer(recorder, req)

			// Check the response body
			if !tc.wantErr {
				assert.Equal(t, jsonReq, recorder.Body.Bytes())
			}

			// Check the error
			assert.True(t, (err != nil) == tc.wantErr)

			// Check the response status code
			assert.Equal(t, tc.expectedStatus, recorder.Code)
		})
	}
}

func TestAPIServer_handleCreateAccount(t *testing.T) {
	// Create a mock storage
	storage := createMockStorage(t)

	// Create a new instance of APIServer with the mock store
	server := NewAPIServer("localhost:8080", storage)

	// Define test cases
	testCases := []struct {
		name       string
		request    pkg.CreateAccountRequest
		expectBody []byte
		status     int
		wantErr    bool
	}{
		{
			name: "Valid account request",
			request: pkg.CreateAccountRequest{
				FirstName: "Bob",
				LastName:  "Ross",
				Password:  "qwerty",
			},
			status:  http.StatusOK,
			wantErr: false,
		},
		{
			name: "Invalid account request with empty FirstName",
			request: pkg.CreateAccountRequest{
				FirstName: "",
				LastName:  "Smith",
				Password:  "123456",
			},
			status:  http.StatusBadRequest,
			wantErr: true,
		},
		{
			name: "Invalid account request with invalid FirstName",
			request: pkg.CreateAccountRequest{
				FirstName: "12423",
				LastName:  "Smith",
				Password:  "123456",
			},
			status:  http.StatusBadRequest,
			wantErr: true,
		},
		{
			name: "Invalid account request with invalid LasttName",
			request: pkg.CreateAccountRequest{
				FirstName: "Bob",
				LastName:  "1687",
				Password:  "123456",
			},
			status:  http.StatusBadRequest,
			wantErr: true,
		},
		{
			name:    "Empty account request",
			request: pkg.CreateAccountRequest{},
			status:  http.StatusBadRequest,
			wantErr: true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert the request body to JSON
			jsonReq, _ := json.Marshal(tc.request)

			// Create a new POST request to the handleCreateAccount endpoint
			req, _ := http.NewRequest("POST", "/account", bytes.NewBuffer(jsonReq))

			// Create a response recorder to capture the response
			recorder := httptest.NewRecorder()

			// The caller to indicate expected use
			storage.EXPECT().CreateAccount(gomock.Any()).Return(nil)

			// Call the handleCreateAccount method with the recorder and request
			err := server.handleCreateAccount(recorder, req)

			// Check the response status code
			assert.Equal(t, tc.status, recorder.Code)

			// Parse the response body into a CreateAccountResponse struct
			var resp pkg.Account
			if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
				t.Error(err)
			}

			// Assert that the response contains not error
			assert.True(t, (err != nil) == tc.wantErr)
		})
	}
}

func TestAPIServer_handleGetAccountByID(t *testing.T) {
	type fields struct {
		storage *mock_store.MockStorage
	}

	account := &pkg.Account{
		ID:                1,
		FirstName:         "Bob",
		LastName:          "Ross",
		EncryptedPassword: "pass",
		Number:            666999,
		Balance:           100,
		CreatedAt:         time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// Define test cases
	testCases := []struct {
		name           string
		account        *pkg.Account
		prepare        func(f *fields)
		method         string
		accountID      int
		expectedStatus int
		expectedBody   []byte
		wantErr        bool
	}{
		{
			name:      "Valid get account by ID",
			account:   account,
			accountID: 1,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(1).Return(account, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: []byte(
				`{
					"id": 1,
					"firstName": "Bob",
					"lastName": "Ross",
					"number": 666999,
					"balance": 100,
					"createdAt": "2022-01-01T00:00:00Z"
				}`,
			),
			wantErr: false,
		},
		{
			name:      "Invalid get account ID",
			account:   account,
			accountID: 2,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(2).Return(nil, fmt.Errorf("not found"))
			},
			expectedBody:   []byte("null"),
			expectedStatus: http.StatusNotFound,
			wantErr:        true,
		},
		{
			name:      "Negative get account ID",
			account:   account,
			accountID: -1,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(-1).Return(nil, fmt.Errorf("invalid negative ID"))
			},
			expectedBody:   []byte("null"),
			expectedStatus: http.StatusNotFound,
			wantErr:        true,
		},
		{
			name:      "Valid deleted account ID",
			account:   account,
			accountID: 1,
			method:    "DELETE",
			prepare: func(f *fields) {
				f.storage.EXPECT().DeleteAccount(1).Return(nil)
			},
			expectedBody:   []byte(`{"deleted":1}`),
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name:           "Invalid method",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   []byte("null"),
			method:         "POST",
			wantErr:        true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Cerate a mock Controller
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := fields{
				storage: mock_store.NewMockStorage(ctrl),
			}

			if tc.prepare != nil {
				tc.prepare(&f)
			}

			// Create a new instance of APIServer with the mock store
			server := NewAPIServer("localhost:8080", f.storage)

			// Create a new method request to the handleGetAccountByID endpoint with the account ID
			req, _ := http.NewRequest(tc.method, fmt.Sprintf("/account/%d", tc.accountID), nil)
			req = mux.SetURLVars(req, map[string]string{"id": strconv.Itoa(tc.accountID)})

			// Create a response recorder to capture the response
			recorder := httptest.NewRecorder()

			// Call the handle method with the recorder and request
			err := server.handleGetAccountByID(recorder, req)

			expectedBody := convertToBytes(string(tc.expectedBody))

			if !tc.wantErr {
				assert.Equal(t, expectedBody, recorder.Body.Bytes())
			}

			assert.True(t, (err != nil) == tc.wantErr)

			// Check the response status code
			assert.Equal(t, tc.expectedStatus, recorder.Code)

		})
	}
}

func convertToBytes(data string) []byte {
	if data == "" {
		return nil
	}

	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.ReplaceAll(data, " ", "")
	data = strings.ReplaceAll(data, "\r", "")
	data = data + "\n"

	return []byte(data)
}

func TestAPIServer_handleGetAccount(t *testing.T) {
	type fields struct {
		storage *mock_store.MockStorage
	}

	// Define test cases
	testCases := []struct {
		name           string
		prepare        func(f *fields)
		expectedStatus int
		wantResponse   []*pkg.Account
		wantErr        bool
	}{
		{
			name: "Not empty get accounts",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().Return(make([]*pkg.Account, 1), nil).Times(1)
			},
			expectedStatus: http.StatusOK,
			wantResponse:   make([]*pkg.Account, 1),
			wantErr:        false,
		},
		{
			name: "Empty get accounts",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().Return(make([]*pkg.Account, 0), nil).Times(1)
			},
			expectedStatus: http.StatusOK,
			wantResponse:   []*pkg.Account{},
			wantErr:        false,
		},
		{ // вернуть ошибку
			name: "Error get accounts",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().
					Return(
						nil,
						fmt.Errorf("Inivalid get accounts"),
					)
			},
			expectedStatus: http.StatusOK,
			wantResponse:   nil,
			wantErr:        true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Cerate a mock Controller
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := fields{
				storage: mock_store.NewMockStorage(ctrl),
			}

			if tc.prepare != nil {
				tc.prepare(&f)
			}

			// Create a new instance of APIServer with the mock store
			server := NewAPIServer("localhost:8080", f.storage)

			// Create a new GET request to the handleGetAccountByID endpoint with the account ID
			req := httptest.NewRequest("GET", "/account", nil)

			// Create a response rr to capture the response
			rr := httptest.NewRecorder()

			// Call the handleGetAccount method with the recorder and request
			err := server.handleGetAccount(rr, req)

			if !tc.wantErr {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}

			var resp []*pkg.Account

			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			if err != nil {
				return
			}

			assert.Equal(t, resp, tc.wantResponse)

			// Check the response status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

		})
	}
}

func TestAPIServer_handleAccount(t *testing.T) {
	type fields struct {
		storage *mock_store.MockStorage
	}

	accounts := make([]*pkg.Account, 0)

	account := &pkg.Account{
		ID:                1,
		FirstName:         "Bob",
		LastName:          "Ross",
		EncryptedPassword: "pass",
		Number:            666999,
		Balance:           100,
		CreatedAt:         time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	accounts = append(accounts, account)

	// Define test cases
	testCases := []struct {
		name           string
		request        pkg.CreateAccountRequest
		prepare        func(f *fields)
		method         string
		expectedStatus int
		expectedBody   []byte
		wantErr        bool
	}{
		{
			name:   "Method GET handleGetAccount",
			method: "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().Return(accounts, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: []byte(
				`[{
					"id": 1,
					"firstName": "Bob",
					"lastName": "Ross",
					"number": 666999,
					"balance": 100,
					"createdAt": "2022-01-01T00:00:00Z"
				}]`,
			),
			request: pkg.CreateAccountRequest{},
			wantErr: false,
		},
		{
			name:   "Method POST handleCreateAccount",
			method: "POST",
			prepare: func(f *fields) {
				f.storage.EXPECT().CreateAccount(gomock.Any()).Return(nil)
			},
			request: pkg.CreateAccountRequest{
				FirstName: "Bob",
				LastName:  "Ross",
				Password:  "qwerty",
			},
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name:           "Invalid method PATCH handleAccount",
			method:         "PATCH",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   []byte("null"),
			wantErr:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Cerate a mock Controller
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := fields{
				storage: mock_store.NewMockStorage(ctrl),
			}

			if tc.prepare != nil {
				tc.prepare(&f)
			}

			// Create a new instance of APIServer with the mock store
			server := NewAPIServer("localhost:8080", f.storage)

			// Convert the request body to JSON
			jsonReq, _ := json.Marshal(tc.request)

			// Create a new method request to the handleAccount endpoint
			req, _ := http.NewRequest(tc.method, "/account", bytes.NewBuffer(jsonReq))

			// Create a response recorder to capture the response
			recorder := httptest.NewRecorder()

			// Call the handleGetAccount method with the recorder and request
			err := server.handleAccount(recorder, req)

			expectedBody := convertToBytes(string(tc.expectedBody))

			// Check ecpectedBody
			if tc.method == "GET" {
				assert.Equal(t, expectedBody, recorder.Body.Bytes())
			} else {
				assert.NotEmpty(t, recorder.Body.Bytes())
			}

			// Check the response status code
			assert.Equal(t, tc.expectedStatus, recorder.Code)

			// Check the error
			assert.True(t, (err != nil) == tc.wantErr)

		})
	}

}

func createMockStorage(t testing.TB) *mock_store.MockStorage {
	t.Helper()

	// Cerate a mock Controller
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a mock storage implementation
	storage := mock_store.NewMockStorage(ctrl)

	return storage
}

func Test_getID(t *testing.T) {
	testCases := []struct {
		name     string
		id       string
		expected int
		wantErr  bool
	}{
		{
			name:     "Test case valid",
			id:       "123",
			expected: 123,
			wantErr:  false,
		},
		{
			name:     "Test case invalid",
			id:       "aaa",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new router using the mux library
			router := mux.NewRouter()

			// Create a mock request with the desired ID parameter
			req := httptest.NewRequest("GET", "/path/{id}", nil)
			req = mux.SetURLVars(req, map[string]string{"id": tc.id})

			// Create a new recorder to capture the response
			recorder := httptest.NewRecorder()

			// Create a new request using the router and recorder
			router.ServeHTTP(recorder, req)

			// Call the function being tested
			id, err := getID(req)

			// Check if the returned ID and error match the expected values
			assert.Equal(t, tc.expected, id)

			// Check the error
			assert.True(t, (err != nil) == tc.wantErr)

		})
	}
}

func Test_permissionDenied(t *testing.T) {
	// Create a new mock response writer
	w := httptest.NewRecorder()

	// Call the function being tested
	permissionDenied(w)

	// Check the response status code
	assert.Equal(t, w.Code, http.StatusForbidden)

	// Check the response body
	expectedBody := `{"error":"permission denied"}` + "\n"

	assert.Equal(t, expectedBody, w.Body.String())
}

func Test_makeHTTPHandleFunc(t *testing.T) {
	testCases := []struct {
		name           string
		apiFunc        apiFunc
		expectedStatus int
		wantErr        bool
	}{
		{
			name: "Test case 1",
			apiFunc: func(w http.ResponseWriter, r *http.Request) error {
				// Perform some logic here
				return nil
			},
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "Test case 2",
			apiFunc: func(w http.ResponseWriter, r *http.Request) error {
				// Perform some logic here
				return errors.New("some error")
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new mock response writer
			w := httptest.NewRecorder()

			// Create a mock request
			req := httptest.NewRequest("GET", "/test", nil)

			// Create a new HTTP handler function using makeHTTPHandleFunc
			handlerFunc := makeHTTPHandleFunc(tc.apiFunc)

			// Call the handler function with the mock response writer and request
			handlerFunc(w, req)

			// Check the response status code
			assert.Equal(t, w.Code, tc.expectedStatus)
		})
	}
}

func Test_createJWT(t *testing.T) {
	// Prepare test data
	account := &pkg.Account{
		Number: 1234567890,
	}

	// Call the function being tested
	token, err := createJWT(account)

	// Check the result
	if err != nil {
		t.Errorf("Failed to create JWT: %v", err)
	}

	// Verify the token
	verifiedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		secret := []byte(os.Getenv("JWT_SECRET"))
		return secret, nil
	})

	_ = verifiedToken
	if err != nil {
		t.Errorf("Failed to parse JWT: %v", err)
	}
}

func Test_validateJWT(t *testing.T) {
	account := &pkg.Account{
		ID:                1,
		FirstName:         "Bob",
		LastName:          "Ross",
		EncryptedPassword: "pass",
		Number:            666999,
		Balance:           100,
		CreatedAt:         time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	testCases := []struct {
		name        string
		tokenHeader string
		tokenMethod jwt.SigningMethod
		validMethod bool
		wantErr     bool
	}{
		{
			name:        "Valid token method",
			tokenMethod: &jwt.SigningMethodHMAC{},
			validMethod: true,
			wantErr:     false,
		},
		{
			name:        "Invalid token method",
			tokenMethod: &jwt.SigningMethodECDSA{},
			validMethod: false,
			wantErr:     true,
		},
	}

	for _, tc := range testCases {

		tokenString, _ := createJWT(account)

		token, err := validateJWT(tokenString)

		// Check the error
		assert.Nil(t, err)

		// Проверка, что token не является nil
		assert.NotNil(t, token)

		// Проверка, что метод подписи токена соответствует ожидаемому значению
		assert.True(t, (tc.tokenMethod.Alg() == token.Method.Alg()) == (err != nil))
	}

}

func Test_withJWTAuth(t *testing.T) {
	type testCase struct {
		name         string
		number       int64
		userID       string
		token        string
		expectedCode int
		msgErr       string
		wantErr      bool
	}

	testCases := []testCase{
		{
			name:         "Valid token with matching account number",
			number:       88992211,
			userID:       "1",
			token:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjo4ODk5MjIxMSwiZXhwaXJlc0F0IjoxNTAwMH0.lFFFV038S9-ZWr6oSzOMbzUIyN3K4BHqY3bvRYXmxmQ",
			expectedCode: http.StatusOK,
			msgErr:       "",
			wantErr:      false,
		},
		{
			name:         "Invalid token",
			number:       88992211,
			userID:       "1",
			token:        "invalid_token_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjowLCJleHBpcmVzQXQiOjE1MDAwfQ.NDCpuBy_ilDA-01aY-GKi8_T2yM5FQh2KiXZTm6m1zc",
			expectedCode: http.StatusForbidden,
			msgErr:       "error:invalid token",
			wantErr:      true,
		},
		{
			name:         "Invalid user id",
			number:       88992211,
			userID:       "a",
			token:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjowLCJleHBpcmVzQXQiOjE1MDAwfQ.NDCpuBy_ilDA-01aY-GKi8_T2yM5FQh2KiXZTm6m1zc",
			expectedCode: http.StatusForbidden,
			msgErr:       "error:permission denied",
			wantErr:      true,
		},
		{
			name:         "Invalid user id",
			number:       88992211,
			userID:       "2",
			token:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjowLCJleHBpcmVzQXQiOjE1MDAwfQ.NDCpuBy_ilDA-01aY-GKi8_T2yM5FQh2KiXZTm6m1zc",
			expectedCode: http.StatusForbidden,
			msgErr:       "error:permission denied",
			wantErr:      true,
		},
		{
			name:         "Invalid user id",
			number:       11224455,
			userID:       "1",
			token:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjowLCJleHBpcmVzQXQiOjE1MDAwfQ.NDCpuBy_ilDA-01aY-GKi8_T2yM5FQh2KiXZTm6m1zc",
			expectedCode: http.StatusForbidden,
			msgErr:       "error:permission denied",
			wantErr:      true,
		},

		// Add more test cases for other conditions
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			mockStorage := createMockStorage(t)

			// Create mock handler
			mockHandler := func(w http.ResponseWriter, r *http.Request) {}

			path := fmt.Sprintf("/account/%s", tc.userID)

			req := httptest.NewRequest("GET", path, nil)

			id, err := strconv.Atoi(tc.userID)

			account := &pkg.Account{
				ID:     id,
				Number: tc.number,
			}

			req.Header.Set("x-jwt-token", tc.token)
			req = mux.SetURLVars(req, map[string]string{"id": tc.userID})

			rr := httptest.NewRecorder()

			handler := withJWTAuth(mockHandler, mockStorage)

			mockStorage.EXPECT().GetAccountByID(account.ID).Return(account, err)

			handler(rr, req)

			// assert.ErrorAs(t, err, tc.err)

			// assert.True(t, (err != nil), tc.validToken)

			assert.Equal(t, rr.Code, tc.expectedCode)
		})
	}
}
