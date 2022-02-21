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
MIIDcDCCAlgCCQCFViruPdGqNjANBgkqhkiG9w0BAQsFADB6MQswCQYDVQQGEwJD
TjEPMA0GA1UECAwGRnVKaWFuMRIwEAYDVQQHDAlaaGFuZ3pob3UxFjAUBgNVBAoM
DUdPLURBSSBDQVJPT1QxFjAUBgNVBAsMDUdPLURBSSBDQVJPT1QxFjAUBgNVBAMM
DUdPLURBSSBDQVJPT1QwHhcNMjIwMjIxMTI1NzA4WhcNMzIwMjE5MTI1NzA4WjB6
MQswCQYDVQQGEwJDTjEPMA0GA1UECAwGRnVKaWFuMRIwEAYDVQQHDAlaaGFuZ3po
b3UxFjAUBgNVBAoMDUdPLURBSSBDQVJPT1QxFjAUBgNVBAsMDUdPLURBSSBDQVJP
T1QxFjAUBgNVBAMMDUdPLURBSSBDQVJPT1QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDXgBAs/0Ilmeug0VzqgeaacE03q6/tQ4A9BvOw1dP577T68fk3
4c55SwK3xOkoCjQAhetVVQvcjAPd2sUFuBreONKDMRptWyJTUDOJq7lPB6Ot8FjX
mIlK/MDP50Wh8bPnaJ7EJsnw0OkgUoIRWfZYrO98B97FfW8sgbjHE0Lg7xihZxF1
aKOYAExGY+ASrv3gzHCA07FixAfLK7K0nJA5hCF+Kf6X9vTzYszv+k34GHe8fh4x
w/m9Fcogyuolz/pS79HyyMobimPoiGn54yW7gsgNUDeF/xNzW/Rz9ARVuxdckMbM
5C0RqspSYjgMmLM8SfWL7//HRwRVF/uMaebxAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAAY6IQqBQfs4xQirPutIZ2aJcrZfgmD2gIetFe8DDdPbZHQz1vnagsjbtenS
HLvUurIdDU9PO1wEGgmSOP4Rfmc41cJP8Uq5o2f5iNRzLrLxu4mhDZowSQf3I42U
SBxFlBqA6ZSRJ3iHT23I8spyaPKjPOTu31RvPNnLWkfQzVWk/6IKGnHpeShThktJ
H6Aivm98iIgO31yhM7i8Ez1UFRsqDqpIltKe7VJohwo1LKtHBZnIlgd5Cz/4fj2q
SNXT1RPEjaAHxrY/I/2x/w0BRPqCr777z/YrVkRKvRcM3P6RfEWdttq7zTKjK4kO
Ie/8k+ZXrhMzEkaILkMMEhCcoVs=
-----END CERTIFICATE-----
`)
	_rootKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,37287504C2944237

pvEq2uVojVUD1BZ0FNJFVZrOuK3AhamCn0rgV5WPNPByX+ZiksggflvZG1PJqzQN
/XJffn7Cxc8wc7cLKb4RQYePfNoE+uAuQHmb7iMye103b759i4l4jGTPbJOqi+zf
/sYlD+SJjsSCuUS+XnKcLEY4/Hq1xZo8QGS2xPQo8OXcDHD2JG6qtXh9GNVRqbHd
v4sDUolbFopjzTWJ0WxuxTIImK1r1L/hvca6O5BEfUdZ6Ff+MCR1JHEXhJIZXARe
+7S/WSDkyx657YM4yGTuoCwylCEQ2Tp6n8cTG4AG/1tuTKev3TIeDmNNXrpBXSNv
gcT0hQB0bhEqA1/S2MGYbDD8/jc2LGHdGUL6FpbKGiaefYT39n2BngEJNWjRzu9i
hqQ4nH3XPVp6+xruy6v583NUlCS3FktmjH8CMmi++NTPRMrSdKS2eFI/bD30uBOV
iQq62MY5vk2ddAapharggYUxp2q9WF7z2n9Fmn6urtBoP51l4t5EH5pWIj8Djwl5
dz2QUCimUNU125ihQ4FM7k7AgKue4rMA7lYxrrw7S7Jy5+rQoc6zujXYkTlCjo4P
ui8zdTbCWPkiINczkmMTh5u/CK5KzNy/t1eRzWaDpnI4AR8TmfscO9fR8KdUhm+O
7o3MvtI0I6RgC954CGRq+YWpIb7VJAyfowp4X6eq1vFvjrOqxNGy3OHMWIPrCgWx
LDHWQIkNm+Zp4tYWpbULvB6DcNNhebgzCL42hM8+7YAuxbJR+QcX6/lb0902suAu
p5/wcYbLeeIPefAedS45NL5+fDVGEMxYNM6CRh74hJ8M/6FDrMbbqWeDC0i/jWs0
wqDwkFha8er1EKHzJORc7EP7hxZw2OBNGAJ2RaGOtmzL0KuzZ2fzWVL48YzmtZIq
Y8Ktq+G6qXfk2+XjkvWIxUCvA1w1r95kqZkJYFp7QD8HMqPeHuv8XGXukzOp5/i7
P6RS+fDxi12lV4Q91Jin08/g3uPWSX4kvsa034VYhh7pYEBkNr8GtiGeev5eLu9r
GoDtHa8/7HLwWxtG+5fCibI2/h+YggNpy7jJNudY7Y6qdmf5caaE7fsCwj7fJBxo
fLgJU8fyQ99D6MjZtFal6YgVTdsYCd1GUvwaJksBWgTcpbQ/dVyy8twysuF2tsfe
sL3yuWkwMnaW8AbnV5x9Len2LQuXiORdzdX+k90WtrrhEY0gMUcr3dDjYhN0ol5d
tURn4LA+grfbkq+8pKT7AsEsX18fQsraTSF9ahtX+q0gnFW0TNIGGWXq0UxledS+
6TpfOTPrCNhPOoa9Xz/PYcM+IX7IzdQgorC7urq+MHsP3QdBFT0w15AEB7rMk2ON
3JvGuVJJKxMmqWsXEL+ehzxM2FhQ9Ow2IlbUfXkvBF804vFiCSk4uD3L+lMStNsj
9NmPCCmsApQUwZv3VA/5hiIOQvzeQPj9oKOnbyl8JahSdf2cqh0oZUDa1caZ9z/t
FQHjfChFX9IU/GgvPx4/Hv+7DjW1b827OM2zQ1711Sp/RqwHe8s7KU0YhzdV1Z/t
F8p5Kc8QVruoPgHYj/N/uBoLx66cXdjUZtTJ8XKb0oPnpPDEPTCCZw==
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
	if err != nil {
		return errors.Wrap(err, "Key证书解析失败")
	}

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
