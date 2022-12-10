#build stage
FROM golang:1.19-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
RUN apk add --no-cache libpcap-dev
WORKDIR /go/src/app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build  -o /go/bin/app -v ./...

#final stage
FROM alpine:3
RUN apk --no-cache add ca-certificates libpcap
COPY --from=builder /go/bin/app /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

#CMD ["./app","-loglevel", "debug", "-iface", "eth0", "-router","172.20.0.6","-iprange", "172.30.0.10-172.30.0.20"]

LABEL Name=icmpreply Version=0.0.1
