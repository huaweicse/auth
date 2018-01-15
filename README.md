### Authentication Plugin for Go-Chassis

This plugin provides the authentication mechanism for Huawei Public Cloud.
The authentication mechanism can be either AK/SK based or token based.
Based on the type this plugin appends the signed auth token or AK/SK in the header of 
each request. The api's of Service-Center, Config-Center and Monitoring Server of
Huawei Public Cloud needs authentication so this plugins adds the auth header for 
these api's.


You can specify the AK/SK in the chassis.yaml of Go-Chassis  
```
cse.credentials.accessKey
cse.credentials.secretKey
```

After signing the header with authourization the Header looks like this  
```
Authorization: Credential=XXX, SignedHeaders=XXX, Signature=XXX
```

