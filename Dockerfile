# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /app
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o app .

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=build /app/app /app/app
ENV PORT=8080
EXPOSE 8080
CMD ["/app/app"]
