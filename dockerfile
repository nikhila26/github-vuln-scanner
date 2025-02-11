# Use the official Golang image as the base image
FROM golang:1.20

# Set the working directory inside the container
WORKDIR /app

# Copy everything from the current directory to /app in the container
COPY . .

# Download dependencies
RUN go mod tidy

# Build the Go application
RUN go build -o vulnscanner main.go

# Expose the application port (matches the one in your code)
EXPOSE 8080

# Run the application
CMD ["./vulnscanner"]
