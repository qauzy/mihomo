package http

import (
	"context"
	"crypto/tls"
	"github.com/metacubex/mihomo/x"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/listener/inner"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader) (*http.Response, error) {
	return HttpRequestWithProxy(ctx, url, method, header, body, "")
}

func HttpRequestWithProxy(ctx context.Context, url, method string, header map[string][]string, body io.Reader, specialProxy string) (*http.Response, error) {
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("X-Version", x.VERSION)
	req.Header.Set("X-UUID", x.MachineData.PlatformUUID+"-"+x.MachineData.BoardSerialNumber+"-M")

	if _, ok := header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", UA())
	}

	if err != nil {
		return nil, err
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	transport := &http.Transport{
		// from http.DefaultTransport
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(address, specialProxy); err == nil {
				return conn, nil
			} else {
				return dialer.DialContext(ctx, network, address)
			}
		},
		TLSClientConfig: ca.GetGlobalTLSConfig(&tls.Config{}),
	}

	client := http.Client{
		Transport: transport,
		Timeout:   60 * time.Second, // 增加请求的整体超时时间
	}
	return client.Do(req)
}
