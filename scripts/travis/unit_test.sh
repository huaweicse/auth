#!/bin/sh
set -e

go get -d -u github.com/stretchr/testify/assert

#mkdir for test
mkdir -p ${GOPATH}/test/auth/conf
mkdir -p ${GOPATH}/test/auth/ServiceAccount
mkdir -p ${GOPATH}/test/auth/secret

cd $GOPATH/src/github.com/huaweicse/auth
#Start unit test
for d in $(go list ./...); do
    echo $d
    echo $GOPATH
    cd $GOPATH/src/$d
    if [ $(ls | grep _test.go | wc -l) -gt 0 ]; then
        go test 
    fi
done
