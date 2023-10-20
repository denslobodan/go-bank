# Compile stage
FROM golang:1.21.1 AS build-env

WORKDIR /go-bank

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-linkmode external -extldflags -static" -o bin/go-bank cmd/main.go

EXPOSE 8080

# Final stage
FROM alpine

EXPOSE 8080

WORKDIR /go-bank

COPY --from=build-env /go-bank /go-bank

CMD ["/bin/go-bank"]
