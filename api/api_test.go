package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mock_store "github.com/denslobodan/go-bank/pkg/mocks"
	pkg "github.com/denslobodan/go-bank/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func Test_handleCreateAccount(t *testing.T) {
	// Create a mock storage
	storage := createMockStorage(t)

	// Create a new instance of APIServer with the mock store
	server := NewAPIServer("localhost:8080", storage)

	// Create an accountRequest
	reqBody := createdAccountRequest("Bob", "Ross", "qwerty")
	// Convert the request body to JSON
	jsonReq, _ := json.Marshal(reqBody)

	// Create a new POST request to the handleCreateAccount endpoint
	req, _ := http.NewRequest("POST", "/account", bytes.NewBuffer(jsonReq))

	// Create a response recorder to capture the response
	recorder := httptest.NewRecorder()

	// The caller to indicate expected use
	storage.EXPECT().CreateAccount(gomock.Any()).Return(nil)

	// Call the handleCreateAccount method with the recorder and request
	server.handleCreateAccount(recorder, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Parse the response body into a CreateAccountResponse struct
	var resp pkg.Account
	json.Unmarshal(recorder.Body.Bytes(), &resp)

	// Assert that the response contains the correct account details
	assert.NotEmpty(t, resp)

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

// Create a request body with the required fields for creating an account
func createdAccountRequest(fName, lName, pass string) pkg.CreateAccountRequest {

	return pkg.CreateAccountRequest{
		FirstName: fName,
		LastName:  lName,
		Password:  pass,
	}
}
