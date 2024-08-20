FROM golang:alpine

WORKDIR /app

COPY . .

RUN go build .

EXPOSE 9090

CMD ["./go-auth-server"]