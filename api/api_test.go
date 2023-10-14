package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mock_store "github.com/denslobodan/go-bank/pkg/mocks"
	pkg "github.com/denslobodan/go-bank/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestAPIServer_handleCreateAccount(t *testing.T) {
	// Create a mock storage
	storage := createMockStorage(t)

	// Create a new instance of APIServer with the mock store
	server := NewAPIServer("localhost:8080", storage)

	// Define test cases
	testCases := []struct {
		name    string
		request pkg.CreateAccountRequest
		status  int
		wantErr bool
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
			server.handleCreateAccount(recorder, req)

			// Check the response status code
			assert.Equal(t, tc.status, recorder.Code)

			// Parse the response body into a CreateAccountResponse struct
			var resp pkg.Account
			json.Unmarshal(recorder.Body.Bytes(), &resp)

			// Assert that the response contains the correct account details
			if tc.wantErr {
				assert.Empty(t, resp)
			} else {
				assert.NotEmpty(t, resp)
			}
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
		Balance:           0,
		CreatedAt:         time.Now().UTC(),
	}

	// Define test cases
	testCases := []struct {
		name           string
		account        *pkg.Account
		prepare        func(f *fields)
		accountID      int
		method         string
		expectedStatus int
		wantErr        bool
	}{
		{
			name:      "Valid get account ID",
			account:   account,
			accountID: 1,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(account.ID).Return(account, nil)
			},
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name:      "Invalid get account ID",
			account:   account,
			accountID: 2,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(2).Return(nil, fmt.Errorf("not found"))
			},
			expectedStatus: http.StatusNotFound,
			wantErr:        true,
		},
		{
			name:      "Negative get account ID",
			account:   account,
			accountID: -1,
			method:    "GET",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccountByID(-1).Return(nil, fmt.Errorf("invalid ID"))
			},
			expectedStatus: http.StatusBadRequest,
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
			expectedStatus: http.StatusOK,
			wantErr:        false,
		},
		{
			name:           "Invalid method",
			expectedStatus: http.StatusBadRequest,
			method:         "POST",
			wantErr:        true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// var err error
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
			req, _ := http.NewRequest(tc.method, fmt.Sprintf("/account/%d", tc.accountID), nil)

			// Create a response recorder to capture the response
			recorder := httptest.NewRecorder()

			if tc.method == "GET" {
				got, err := f.storage.GetAccountByID(tc.accountID)

				if got != nil {
					WriteJSON(recorder, http.StatusOK, got)
				} else {
					assert.Error(t, err)
				}

				if err != nil || account == nil {
					WriteJSON(recorder, http.StatusNotFound, nil)
					assert.Error(t, err)
					return
				}

			} else if tc.method == "DELETE" {
				f.storage.DeleteAccount(tc.accountID)
			} else {
				recorder.WriteHeader(http.StatusBadRequest)
			}

			// Call the handle method with the recorder and request
			server.handleGetAccountByID(recorder, req)

			assert.Equal(t, tc.expectedStatus, recorder.Code)

		})
	}
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
		wantEmpty      bool
	}{
		{
			name: "Not empty get accounts",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().Return(make([]*pkg.Account, 1), nil).Times(2)
			},
			expectedStatus: http.StatusOK,
			wantEmpty:      false,
		},
		{
			name: "Empty get accounts",
			prepare: func(f *fields) {
				f.storage.EXPECT().GetAccounts().Return(make([]*pkg.Account, 0), nil).Times(2)
			},
			expectedStatus: http.StatusOK,
			wantEmpty:      true,
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
			req, _ := http.NewRequest("GET", "/account", nil)

			// Create a response recorder to capture the response
			recorder := httptest.NewRecorder()

			resp, _ := f.storage.GetAccounts()

			// Call the handleGetAccount method with the recorder and request
			server.handleGetAccount(recorder, req)

			// Check the response status code
			assert.Equal(t, tc.expectedStatus, recorder.Code)
			// Assert that the response contains the correct account details
			if !tc.wantEmpty {
				assert.NotEmpty(t, resp)
			} else {
				assert.Empty(t, resp)
			}
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
