# UPDATED FILE
# Instructions for Docker to build the user-service image.

FROM golang:1.23-alpine
# Set the working directory for all subsequent commands
WORKDIR /app

# Copy go module files and download dependencies
COPY go.* ./
RUN go mod download

# Copy the rest of the source code into the workdir
COPY *.go ./

# Build the Go application and output the executable IN the workdir
RUN go build -o /app/user-service-app

# Expose the port
EXPOSE 8080

# Execute the application from its location in the workdir
CMD [ "/app/user-service-app" ]
