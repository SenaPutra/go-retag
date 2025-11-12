# Build
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/retag-api .

# Run with Docker CLI available
FROM docker:27-cli
ENV ADDR=:8080
EXPOSE 8080
COPY --from=build /out/retag-api /usr/local/bin/retag-api
ENTRYPOINT ["/usr/local/bin/retag-api"]
