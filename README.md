# uriauth
URI Auth

## example

    package main

    import (
        "fmt"
        "time"

        "github.com/GiterLab/uriauth"
    )

    func main() {
        uri := "rtmp://ipc.example.com/live/test?a=123&b=456" // original uri
        key := "<input your key>"                             // private key of authorization
        exp := time.Now().Unix() + 3600                       // expiration time: 1 hour after current itme
        authURI, err := uriauth.URIAuth(uri, "0", "0", key, exp)
        if err != nil {
            fmt.Println(err)
        }
        // 签名URL结果
        fmt.Printf("Auth: %s\n", authURI)
        // 对 authURI 进行校验
        fmt.Println(uriauth.URIAuthCheck(authURI, key))
        // 对 authURI 提取 path & args
        fmt.Println(uriauth.URIAuthParse(authURI))
    }

    $ go run main.go
    Auth: rtmp://ipc.example.com/live/test?a=123&b=456&auth_key=1640353115-0-0-55b1cb678d9552411734898a14802711
    true
    /live/test map[a:[123] auth_key:[1640353115-0-0-55b1cb678d9552411734898a14802711] b:[456]] <nil>
