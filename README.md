# Authentication Plugin for Go-Chassis
[![Build Status](https://travis-ci.org/ServiceComb/auth.svg?branch=master)](https://travis-ci.org/ServiceComb/auth)
This plugin provides the authentication mechanism for Huawei Public Cloud.
The authentication mechanism can be either AK/SK based or token based.
Based on the type this plugin appends the signed auth token or AK/SK in the header of 
each request. The api's of Service-Center, Config-Center and Monitoring Server of
Huawei Public Cloud needs authentication so this plugins adds the auth header for 
these api's.

# how to use in go chassis 
1.You can specify the AK/SK in the auth.yaml of Go-Chassis  
```
cse.credentials.accessKey
cse.credentials.secretKey
```


2.Import in your main.go before other imports
```go
import _ "github.com/huaweicse/auth/adaptor/gochassis"
```

After signing the header with authourization the Header looks like this  
```
Authorization: Credential=XXX, SignedHeaders=XXX, Signature=XXX
```








==========================================

For third_party/forked/datastream/aws(github.com/datastream/aws)

Copyright (c) 2014, Xianjie
All rights reserved.


========================================================================

For vendor/github.com/huaweicse/auth/third_party/forked/datastream/aws:

========================================================================

See third_party/forked/datastream/aws/LICENSE
