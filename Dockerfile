FROM golang:1.11 AS builder

WORKDIR /go/src/github.com/dimuls/rkn-bypasser
COPY . .

RUN go get -d -v ./... && \
CGO_ENABLED=0 go install -v ./...



FROM alpine:3.8

ENV BIND_ADDR=0.0.0.0:8000 TOR_ADDR=tor:9150

WORKDIR /

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/rkn-bypasser /
COPY --from=builder /go/src/github.com/dimuls/gotapdance/assets /
COPY additional-ips.yml /

EXPOSE 8000

ENTRYPOINT ["/rkn-bypasser", "--with-additional-ips"]
