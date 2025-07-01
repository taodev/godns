FROM golang:1.24-alpine AS builder
LABEL maintainer="taodev <taodev@gmail.com>"
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -v -trimpath -o godns -ldflags "-s -w" ./cmd/godns && \
		sh ./scripts/update-geosite.sh

# 第二阶段：极简运行环境
FROM alpine:latest
LABEL maintainer="taodev <taodev@gmail.com>"
COPY --from=builder /app/godns /usr/local/bin/godns
COPY --from=builder /app/geosite.dat /var/lib/godns/geosite.dat
RUN apk add --no-cache bash tzdata ca-certificates
EXPOSE 53/udp
EXPOSE 80/tcp
EXPOSE 443/tcp
ENTRYPOINT ["godns"]
