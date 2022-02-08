all: test
	go build -o ./enc *.go

test:
	go test .
