package uriauth

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

func md5sum(src string) string {
	h := md5.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
}

// URIAuthParse 从URL中提取出 path & args
func URIAuthParse(uri string) (path string, args url.Values, err error) {
	_, err = regexp.Compile(`^(http://|https://|ws://|wss://|rtmp://|rtsp://)?([^/?]+)(/[^?]*)?(\\?.*)?$`)
	if err != nil {
		return "", nil, err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", nil, err
	}
	args, err = url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil, err
	}
	return u.Path, args, nil
}

// URIAuth 视频URL签名
// uri URL链接
// rand 算法，默认为0
// uid 用户ID，默认为0
// key 用户签名key，不可公开，不可为空
// exp 过期时间戳, 单位秒
func URIAuth(uri, rand, uid, key string, exp int64) (string, error) {
	var scheme, host, path, args string

	if key == "" {
		return "", errors.New("key shoud not be empty")
	}

	p, err := regexp.Compile(`^(http://|https://|ws://|wss://|rtmp://|rtsp://)?([^/?]+)(/[^?]*)?(\\?.*)?$`)
	if err != nil {
		return "", err
	}
	m := p.FindStringSubmatch(uri)
	if len(m) == 5 {
		scheme, host, path, args = m[1], m[2], m[3], m[4]
	} else {
		scheme, host, path, args = "rtmp://", "", "/", ""
	}
	if rand == "" {
		rand = "0"
	}
	if uid == "" {
		uid = "0"
	}
	hashValue := md5sum(fmt.Sprintf("%s-%d-%s-%s-%s", path, exp, rand, uid, key))
	authKey := fmt.Sprintf("%d-%s-%s-%s", exp, rand, uid, hashValue)
	if len(args) != 0 {
		return fmt.Sprintf("%s%s%s%s&auth_key=%s", scheme, host, path, args, authKey), nil
	} else {
		return fmt.Sprintf("%s%s%s%s?auth_key=%s", scheme, host, path, args, authKey), nil
	}
}

// URIAuthCheck 验证签名串是否合法
// uri URL链接
// key 用户签名key，不可公开, 不可为空
func URIAuthCheck(uri, key string) bool {
	if key == "" {
		return false
	}

	path, args, err := URIAuthParse(uri)
	if err != nil {
		return false
	}

	if v, ok := args["auth_key"]; ok {
		if len(v) == 1 {
			m := strings.Split(v[0], "-")
			if len(m) == 4 {
				exp, rand, uid, hashValue := m[0], m[1], m[2], m[3]
				if hashValue == md5sum(fmt.Sprintf("%s-%s-%s-%s-%s", path, exp, rand, uid, key)) {
					return true
				}
			}
		}
	}
	return false
}
