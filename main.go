package main

func main() {
	server := NewAPIServer(":3030")
	server.Run()
}
