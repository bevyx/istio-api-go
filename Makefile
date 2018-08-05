all: generate 

# Generate code
generate:
	go generate ./pkg/...