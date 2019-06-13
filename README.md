# huawei cloud auth 
[![Build Status](https://travis-ci.org/ServiceComb/auth.svg?branch=master)](https://travis-ci.org/ServiceComb/auth)
This provides the authentication mechanism for Huawei Public Cloud.
The authentication mechanism can be either AK/SK based or token based.

# how to use 
```go
sign, err := auth.GetSignFunc(ak, sk, project)
req, err := http.NewRequest("GET", "cce.cn-north-1.myhuaweicloud.com", nil)
err = sign(r)
resp, err := client.Do(req)
```



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
