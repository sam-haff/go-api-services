FROM golang:alpine

WORKDIR /app

COPY . .

RUN go build .

EXPOSE 9091

CMD ["./go-api-server"]