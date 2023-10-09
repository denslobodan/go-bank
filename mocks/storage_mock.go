// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/denslobodan/go-bank/pkg (interfaces: Storage)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	pkg "github.com/denslobodan/go-bank/pkg"
	gomock "github.com/golang/mock/gomock"
)

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// CreateAccount mocks base method.
func (m *MockStorage) CreateAccount(arg0 *pkg.Account) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccount", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAccount indicates an expected call of CreateAccount.
func (mr *MockStorageMockRecorder) CreateAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccount", reflect.TypeOf((*MockStorage)(nil).CreateAccount), arg0)
}

// DeleteAccount mocks base method.
func (m *MockStorage) DeleteAccount(arg0 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAccount", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAccount indicates an expected call of DeleteAccount.
func (mr *MockStorageMockRecorder) DeleteAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAccount", reflect.TypeOf((*MockStorage)(nil).DeleteAccount), arg0)
}

// DeleteAllAccounts mocks base method.
func (m *MockStorage) DeleteAllAccounts() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAllAccounts")
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllAccounts indicates an expected call of DeleteAllAccounts.
func (mr *MockStorageMockRecorder) DeleteAllAccounts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllAccounts", reflect.TypeOf((*MockStorage)(nil).DeleteAllAccounts))
}

// GetAccountByID mocks base method.
func (m *MockStorage) GetAccountByID(arg0 int) (*pkg.Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountByID", arg0)
	ret0, _ := ret[0].(*pkg.Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountByID indicates an expected call of GetAccountByID.
func (mr *MockStorageMockRecorder) GetAccountByID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountByID", reflect.TypeOf((*MockStorage)(nil).GetAccountByID), arg0)
}

// GetAccountByNumber mocks base method.
func (m *MockStorage) GetAccountByNumber(arg0 int) (*pkg.Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountByNumber", arg0)
	ret0, _ := ret[0].(*pkg.Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountByNumber indicates an expected call of GetAccountByNumber.
func (mr *MockStorageMockRecorder) GetAccountByNumber(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountByNumber", reflect.TypeOf((*MockStorage)(nil).GetAccountByNumber), arg0)
}

// GetAccounts mocks base method.
func (m *MockStorage) GetAccounts() ([]*pkg.Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccounts")
	ret0, _ := ret[0].([]*pkg.Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccounts indicates an expected call of GetAccounts.
func (mr *MockStorageMockRecorder) GetAccounts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccounts", reflect.TypeOf((*MockStorage)(nil).GetAccounts))
}

// UpdateAccount mocks base method.
func (m *MockStorage) UpdateAccount(arg0 *pkg.Account) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateAccount", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateAccount indicates an expected call of UpdateAccount.
func (mr *MockStorageMockRecorder) UpdateAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAccount", reflect.TypeOf((*MockStorage)(nil).UpdateAccount), arg0)
}
