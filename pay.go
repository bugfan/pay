package pay

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type ApplePayStatus int

const (
	ApplePayStatusOK                  ApplePayStatus = 0     //收据验证OK
	ApplePayStatusErrorJson           ApplePayStatus = 21000 //App Store无法读取您提供的JSON对象。
	ApplePayStatusErrorReceiptData    ApplePayStatus = 21002 //该receipt-data属性中的数据格式错误或丢失。
	ApplePayStatusErrorReceiptInvalid ApplePayStatus = 21003 //收据无法认证。
	ApplePayStatusErrorSharePassword  ApplePayStatus = 21004 //您提供的共享密码与您帐户的文件共享密码不匹配。
	ApplePayStatusErrorServer         ApplePayStatus = 21005 //收据服务器当前不可用。
	ApplePayStatusErrorReceiptExpired ApplePayStatus = 21006 //该收据有效，但订阅已过期。当此状态代码返回到您的服务器时，收据数据也会被解码并作为响应的一部分返回。仅针对自动续订的iOS 6样式交易收据返回。
	ApplePayStatusErrorReceiptSandbox ApplePayStatus = 21007 //该收据来自测试环境，但已发送到生产环境以进行验证。而是将其发送到测试环境。
	ApplePayStatusErrorReceiptProd    ApplePayStatus = 21008 //该收据来自生产环境，但是已发送到测试环境以进行验证。而是将其发送到生产环境。
	ApplePayStatusErrorReceiptNoAuth  ApplePayStatus = 21010 //此收据无法授权。就像从未进行过购买一样对待。
	ApplePayStatusErrorInternalMin    ApplePayStatus = 21100 //21100~21199 内部数据访问错误。
	ApplePayStatusErrorInternalMax    ApplePayStatus = 21199 //21100~21199 内部数据访问错误。
)

func NewVerifier(sharePassword, verifyURL string) *Verifier {
	verifier := &Verifier{
		SharePassword: sharePassword,
		VerifyURL:     verifyURL,
		client:        new(http.Client),
	}
	verifier.initRequestClient()
	return verifier
}

//Content-Type: application/json
type Verifier struct {
	SharePassword string
	VerifyURL     string
	client        *http.Client
}

func (s *Verifier) VerifyReceiptWithObject(o *VerifyRequestBody) (*VerifyResponseBody, error) {
	data, _ := json.Marshal(o)
	body := bytes.NewBuffer(data)
	_, resData, err := s.request(http.MethodPost, s.VerifyURL, map[string]string{}, body)
	if err != nil {
		return nil, err
	}
	res := &VerifyResponseBody{}
	err = json.Unmarshal(resData, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
func (s *Verifier) toVerifyReceiptBytes(receipt string) []byte {
	o := &VerifyRequestBody{
		ReceiptData: receipt,
		Password:    s.SharePassword,
	}
	data, _ := json.Marshal(o)
	return data
}
func (s *Verifier) VerifyReceipt(receipt string) ([]byte, error) {
	data := s.toVerifyReceiptBytes(receipt)
	body := bytes.NewBuffer(data)
	_, resData, err := s.request(http.MethodPost, s.VerifyURL, map[string]string{}, body)
	return resData, err
}
func (s *Verifier) request(method, target string, headers map[string]string, body io.Reader) (int, []byte, error) {
	req, _ := http.NewRequest(method, target, body)
	req.Header.Add("cache-control", "no-cache")
	req.Close = true
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := s.client.Transport.RoundTrip(req)
	if err != nil {
		return -1, nil, err
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	return res.StatusCode, data, err
}
func (s *Verifier) initRequestClient() {
	netTransport := &http.Transport{
		Dial: func(netw, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(netw, addr, time.Second*time.Duration(20))
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		DisableKeepAlives:     true,
		MaxIdleConnsPerHost:   20,
		ResponseHeaderTimeout: time.Second * time.Duration(20),
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	s.client.Timeout = time.Second * 30
	s.client.Transport = netTransport
}

type VerifyRequestBody struct {
	ReceiptData            string `json:"receipt-data"` //Base64-encoded
	Password               string `json:"password"`
	ExcludeOldTransactions bool   `json:"exclude-old-transactions"` // Set this value to true for the response to include only the latest renewal transaction for any subscriptions. Use this field only for app receipts that contain auto-renewable subscriptions.
}

type VerifyResponseBody struct {
	Environment        string      `json:"environment"`
	IsRetryable        bool        `json:"is-retryable"`
	LatestReceipt      string      `json:"latest_receipt"`
	LatestReceiptInfo  interface{} `json:"latest_receipt_info"`
	PendingRenewalInfo interface{} `json:"pending_renewal_info"`
	Receipt            interface{} `json:"receipt"`
	Status             int         `json:"status"` // 0代表收据正常
}

func NewNotification() *Notification {
	return &Notification{}
}

type Notification struct {
	Header    *Header    `json:"header"`
	Payload   *Payload   `json:"payload"`
	Signature *Signature `json:"signature"`
}

func (s *Notification) Parse(data string) error {
	header, payload, sign, err := parseJWS(data)
	if err != nil {
		return err
	}
	s.Header = header
	s.Payload = payload
	s.Signature = sign
	return nil
}

func parseJWS(data string, args ...string) (*Header, *Payload, *Signature, error) {
	arr := strings.Split(data, ".")
	if len(arr) != 3 {
		return nil, nil, nil, errors.New("error data")
	}

	decoded, err := base64.RawStdEncoding.DecodeString(arr[0])
	if err != nil {
		return nil, nil, nil, err
	}
	header := &Header{}
	err = json.Unmarshal(decoded, header)
	if err != nil {
		return nil, nil, nil, err
	}
	decoded, err = base64.RawStdEncoding.DecodeString(arr[1])
	if err != nil {
		return nil, nil, nil, err
	}
	payload := &Payload{}
	err = json.Unmarshal(decoded, payload)
	if err != nil {
		return nil, nil, nil, err
	}
	sign, _ := (interface{}(arr[2])).(*Signature)

	return header, payload, sign, nil
}

func parseJWS2(data string, args ...string) (*Header, map[string]string, *Signature, error) {
	arr := strings.Split(data, ".")
	if len(arr) != 3 {
		return nil, nil, nil, errors.New("error data")
	}

	decoded, err := base64.RawStdEncoding.DecodeString(arr[0])
	if err != nil {
		return nil, nil, nil, err
	}
	header := &Header{}
	err = json.Unmarshal(decoded, header)
	if err != nil {
		return nil, nil, nil, err
	}
	decoded, err = base64.RawStdEncoding.DecodeString(arr[1])
	if err != nil {
		return nil, nil, nil, err
	}
	payload := make(map[string]string, 0)
	err = json.Unmarshal(decoded, payload)
	if err != nil {
		return nil, nil, nil, err
	}
	sign, _ := (interface{}(arr[2])).(*Signature)

	return header, payload, sign, nil
}

type Header struct {
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
}
type Payload struct {
	NotificationType string      `json:"notificationType"`
	SubType          string      `json:"subtype"`
	NotificationUUID string      `json:"notificationUUID"`
	Data             PayloadData `json:"data"`
	Version          string      `json:"version"`
}
type PayloadData struct {
	BundleId              string `json:"bundleId"`
	BundleVersion         string `json:"bundleVersion"`
	Environment           string `json:"environment"`
	SignedTransactionInfo string `json:"signedTransactionInfo"`
	SignedRenewalInfo     string `json:"signedRenewalInfo"`
}
type Signature string

func NewNotificationMap(data string) (*NotificationMap, error) {
	header, payload, sign, err := parseJWS2(data)
	if err != nil {
		return nil, err
	}
	return &NotificationMap{
		header:    header,
		signature: sign,
		payload:   payload,
	}, nil
}

type NotificationMap struct {
	header    *Header
	signature *Signature
	payload   map[string]string
}

func (n NotificationMap) HeaderMap() *Header {
	return n.header
}
func (n NotificationMap) PayloadMap() map[string]string {
	return n.payload
}
