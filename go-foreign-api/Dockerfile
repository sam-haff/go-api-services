FROM golang:alpine

WORKDIR /app

COPY . .

RUN go build .

EXPOSE 9092

CMD ["./go-foreign-api"]