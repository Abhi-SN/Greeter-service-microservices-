FROM golang:1.23-alpine
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY *.go ./
# Build the executable inside the /app directory
RUN go build -o /app/greeter-service-app
EXPOSE 8080
# Execute the app from the /app directory
CMD [ "/app/greeter-service-app" ]
