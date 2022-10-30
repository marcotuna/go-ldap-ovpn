# Build
FROM golang:1.19-alpine AS build

# Install dependencies
RUN apk update && apk upgrade && apk add --no-cache \
  make git

WORKDIR /app

COPY . .

RUN make linux

# Final container
FROM alpine:3.16

WORKDIR /app

COPY --from=build /app/bin/linux/go-ldap-ovpn /app/

RUN chmod u+x /app/go-ldap-ovpn

# Start
ENTRYPOINT [ "/app/go-ldap-ovpn" ]