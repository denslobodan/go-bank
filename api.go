package main

import "net/http"

type APIServer struct {
	listenAddr string
}

func NewAPIServer(listenAddr string) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
	}
}

func (s *APIServer) Run() {

}

func (ss APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (ss APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (ss APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (ss APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	return nil
}
