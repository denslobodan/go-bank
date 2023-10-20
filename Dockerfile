FROM golang:1.21.1-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

COPY . ./

RUN go build -o bin/go-bank cmd/main.go

EXPOSE 3030

CMD ["./bin/go-bank"]
