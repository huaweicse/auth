#!/bin/sh
set -e

go get -d -u github.com/stretchr/testify/assert

cd $GOPATH/src/github.com/ServiceComb/auth
#Start unit test
for d in $(go list ./...); do
    echo $d
    echo $GOPATH
    cd $GOPATH/src/$d
    if [ $(ls | grep _test.go | wc -l) -gt 0 ]; then
        go test 
    fi
done
