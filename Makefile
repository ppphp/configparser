
fmt:
	gofmt -s -w .

test:fmt
	go test ./... -count=1 -v -cover -race -test.bench=. -test.benchmem
