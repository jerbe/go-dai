package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/jerbe/go-dai/cache"
	"github.com/pkg/errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var (
	rootCa  *x509.Certificate // CA证书
	rootKey *rsa.PrivateKey   // 证书私钥
)

var (
	_rootCa = []byte(`-----BEGIN CERTIFICATE-----
MIIDtDCCApwCCQDBidwpS4lIGTANBgkqhkiG9w0BAQUFADCBmzELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBkZ1amlhbjEPMA0GA1UEBwwGWGlhbWVuMSIwIAYDVQQKDBlK
ZXJiZSBUZWNobm9sb2d5IENvLiBMdGQuMSIwIAYDVQQLDBlKZXJiZSBUZWNobm9s
b2d5IENvLiBMdGQuMSIwIAYDVQQDDBlKZXJiZSBUZWNobm9sb2d5IFJvb3QgQ0Eg
MB4XDTIyMDIyMTE2Mzk1M1oXDTIzMDIyMTE2Mzk1M1owgZsxCzAJBgNVBAYTAkNO
MQ8wDQYDVQQIDAZGdWppYW4xDzANBgNVBAcMBlhpYW1lbjEiMCAGA1UECgwZSmVy
YmUgVGVjaG5vbG9neSBDby4gTHRkLjEiMCAGA1UECwwZSmVyYmUgVGVjaG5vbG9n
eSBDby4gTHRkLjEiMCAGA1UEAwwZSmVyYmUgVGVjaG5vbG9neSBSb290IENBIDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9EY0w6YWnWzo5MzU8vKvNA
gUsQ11q3uGPJwUltmght2W3nFxTMXhQ6I1zpnO/c3LYQemu37j0be3xRT2OuJ8vz
UibCnVJIN2BIwT2ldGWd9eXs47a4YCnqm/4uH4Hry3pbtLVAsQjs51ACNwdyZm9K
fQKDJd216/5Kv3TaRj8bUair8sQ5RXX9fjWYFiZgz3rNkki20OF8sKDhV3H7dWEr
pPkH+Jh1YeVCKK80kQVqXqSEP4CXAQS8YyX6+gWH9XfQdLj7+Zeoi3F4LodTttau
KtuvLgyYRBSVId2+68PrYELykgdRekiw6ABOWgrMqdELM3CAVH4l2R6utJIte6cC
AwEAATANBgkqhkiG9w0BAQUFAAOCAQEAE2jlcp4UT3hKRQlwLSZ0abyFFNeEukHy
D8ftpjsv+3LZt3GkkQc/a389iHbzNA4pNoIr3dq0iDJG0zpc5ouCY4hAd+7fm5K3
z+rl9W4sw76bXzvpyrWVrjnmfcbU3J2CHeyTKkKgx8IfR7rawpAZFG8PMX7eHrEZ
eIR+P8m61zNjUF5SrC5MyigyedgaWFHD0kvVZOqf46rIXgiZFncENX4tNp74hN1O
xtTf9fc3mVF9fj0FSB3DKDVar9JHvpeuLAo6bcEpZXaVES7RiDH8tusNP6Ted6nQ
S//kpdxTSdXGDac4qp9HSLkhTSntnmJVwBCWxmTZ16DjMupfwwMlDQ==
-----END CERTIFICATE-----
`)

	_rootKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv0RjTDphadbOjkzNTy8q80CBSxDXWre4Y8nBSW2aCG3ZbecX
FMxeFDojXOmc79zcthB6a7fuPRt7fFFPY64ny/NSJsKdUkg3YEjBPaV0ZZ315ezj
trhgKeqb/i4fgevLelu0tUCxCOznUAI3B3Jmb0p9AoMl3bXr/kq/dNpGPxtRqKvy
xDlFdf1+NZgWJmDPes2SSLbQ4XywoOFXcft1YSuk+Qf4mHVh5UIorzSRBWpepIQ/
gJcBBLxjJfr6BYf1d9B0uPv5l6iLcXguh1O21q4q268uDJhEFJUh3b7rw+tgQvKS
B1F6SLDoAE5aCsyp0QszcIBUfiXZHq60ki17pwIDAQABAoIBADDXJsANXFipeH9P
z1F8CuyouRtRBpzssxIQL+IvMZkba90rmHJAKXniyqrsIJ4DePyowooFIrnJ7cN2
A97BVvo2fPDW21Nqi3FzwpyaRlm4d1UqI4/CDxRFC2ZhorwLWR86ka+DAHH2BK8i
kai+JrgefkOI979guA1sSu1s22k7gJg7QZfux7h+VUdHzO1pc1RNTqkV4f6N14Aj
FrVcaCYC+EDqYkb5M7MzfvHxkudDiv/2rBXiQnmMnOvipTds7QgSJtCQsrSS5CIv
jybV9wEWQFBjIfXr20vEzxC2DmzrVrBXI8yFxGQ4PaA3IAk1WSRRRDQqGosUfb7k
Dn1vjYECgYEA4tXnSZE78PrbhR4vBAGxQ3W6zB3id+1Kz8VFaBv7u7wDrZAoSZ/U
jAjEaj1xGBPFVOFYta2Z9u7OZzqzE7HcyKs2sgVGidC5s8YNkyNbBDz8ipkJtrtK
EYt9tXBwcAhVE3ikiDHB6zmIQYDqfWJVOqKFNXXcCNsaBGfUXun8b2cCgYEA19vH
1ISn8iVYQFJNwxVtth8pJ5MKouTuP4xgH/ly2D+kPMzFQxrHnnazOJI3abHst5fK
wHE33gRh3nq+0bhmKXbnB2Qf2w2BaQIE3/o8IWm/jkLOy0SsNg9DKTfTTrqBLi9w
Ep66BoAmb0R4AS7REi3rqkfzFLeDcWntBaUKKcECgYEAxtPh8L0qAleQtYU4htWI
8G2wd5w2VxKbAbWT2ea1Z+AshSUX+zjq0Hga2ljS2dzymi0QWec6TpUSPK/aKgg8
U3Sn87DmHITlUavnWDKkY/mlD0OHnTFbgjd3z+Mn2zuifve/mFWs+acrROdgItlf
hY7RHoQZg3Wxv2zXXP7SMz8CgYBOI7VW7R6OvY4Q2rpjoGIyx1zygnwbM5w7TOmP
KZG1TnR5vfa6r/sLFhUSqXt9u3bhjwVKXLHIoPV8wBpLeOEiqXRAbLJLbbwm8yAo
pEEYJ1u8d9q8IoPknenGBftsSH9y5KFBXEwjBkjjhnmalAQC/LSO07TfDv96EspG
fNQNAQKBgQCdDO6I7XQCpFhMu5aXAnJRMQX14yyJSUz7H7Pq4hQ85cbyoBlY57i7
tFXh+53yLQmMZL64HAssy7zSSjFv9cSi0U2Cy+dLXf7GVMGjzPNrpkB+XsEyKvJ7
LKX/KAWoOSTuhyBfet8zktGOpWBeXWkTI3hP8xgOAyqm6+3SqeAYWA==
-----END RSA PRIVATE KEY-----

`)
)

var certCache *cache.Cache

func init() {
	certCache = cache.NewCache()

	if err := loadRootCa(); err != nil {
		panic(err)
	}
	if err := loadRootKey(); err != nil {
		panic(err)
	}
}

func GetCertificate(host string) (tls.Certificate, error) {
	certificate, err := certCache.GetOrStore(host, func() (interface{}, error) {
		host, _, err := net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
		certByte, priByte, err := generatePem(host)
		if err != nil {
			return nil, err
		}
		certificate, err := tls.X509KeyPair(certByte, priByte)
		if err != nil {
			return nil, err
		}
		return certificate, nil
	})
	return certificate.(tls.Certificate), err
}
func generatePem(host string) ([]byte, []byte, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)   //把 1 左移 128 位，返回给 big.Int
	serialNumber, _ := rand.Int(rand.Reader, max) //返回在 [0, max) 区间均匀随机分布的一个随机值
	template := x509.Certificate{
		SerialNumber: serialNumber, // SerialNumber 是 CA 颁布的唯一序列号，在此使用一个大随机数来代表它
		Subject: pkix.Name{ //Name代表一个X.509识别名。只包含识别名的公共属性，额外的属性被忽略。
			CommonName: host,
		},
		NotBefore:      time.Now().AddDate(-1, 0, 0),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, //KeyUsage 与 ExtKeyUsage 用来表明该证书是用来做服务器认证的
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},               // 密钥扩展用途的序列
		EmailAddresses: []string{"forward.nice.cp@gmail.com"},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	priKey, err := generateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	cer, err := x509.CreateCertificate(rand.Reader, &template, rootCa, &priKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{ // 证书
			Type:  "CERTIFICATE",
			Bytes: cer,
		}), pem.EncodeToMemory(&pem.Block{ // 私钥
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priKey),
		}), err
}

// 秘钥对 生成一对具有指定字位数的RSA密钥
func generateKeyPair() (*rsa.PrivateKey, error) {
	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "密钥对生成失败")
	}

	return priKey, nil
}

// 加载根证书
func loadRootCa() error {
	p, _ := pem.Decode(_rootCa)
	var err error
	rootCa, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		return errors.Wrap(err, "CA证书解析失败")
	}

	return nil
}

// 加载根Private Key
func loadRootKey() error {
	p, _ := pem.Decode(_rootKey)
	var err error
	rootKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	// key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return errors.Wrap(err, "Key证书解析失败")
	}
	// rootKey = key.(*rsa.PrivateKey)

	return err
}

// 获取证书原内容
func GetCaCert() []byte {
	return _rootCa
}

// 添加信任跟证书至钥匙串
func AddTrustedCert() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	fileName := dir + "/caRootCert.crt"
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer os.Remove(fileName)
	defer file.Close()

	file.Write(_rootCa)

	var command string
	switch runtime.GOOS {
	case "darwin":
		command = fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", fileName)
	case "windows":
		command = fmt.Sprintf("certutil -addstore -f \"ROOT\" %s", fileName)
	default:
		return errors.New("仅支持MaxOS/Windows系统")
	}

	return shell(command)
}

// 执行shell命令
func shell(command string) error {
	cmd := exec.Command("sh", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return errors.Wrap(err, "")
	}
	return errors.Wrap(cmd.Wait(), out.String())
}
