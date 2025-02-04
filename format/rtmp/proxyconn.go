package rtmp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

type ClientInfo struct {
	ClientCode string `json:"clientCode"`
	SignSecret string `json:"signSecret"`
	Secret     string `json:"secret"`
}

type RegisterInfo struct {
	ClientCode string `json:"clientCode"`
	DateStr    string `json:"dateStr"`
	Sign       string `json:"sign"`
}

const (
	UnEncrypt = iota + 1
	AES
)

type ProxyConnOption struct {
	encryptType int
	clientCode  string
	signSecret  string
	encryptKey  []byte
}

func NewProxyConnOption(encryptType int, clientCode string, signSecret string, encryptKey []byte) ProxyConnOption {
	return ProxyConnOption{
		encryptType: encryptType,
		clientCode:  clientCode,
		signSecret:  signSecret,
		encryptKey:  encryptKey,
	}
}

func NewUnEncryptProxyConnOption() ProxyConnOption {
	return ProxyConnOption{
		encryptType: UnEncrypt,
		clientCode:  "",
		signSecret:  "",
		encryptKey:  nil,
	}
}

type ProxyConn struct {
	err     error
	conn    net.Conn
	readbuf []byte
	ProxyConnOption
}

func newClientProxyConn(conn net.Conn, proxyConnOption ProxyConnOption) (proxyConn *ProxyConn) {
	proxyConn = &ProxyConn{
		err:             nil,
		conn:            conn,
		ProxyConnOption: proxyConnOption,
	}
	if proxyConnOption.encryptType == UnEncrypt {
		return
	}
	if proxyConnOption.encryptType == AES {
		// register to server
		currentDateStr := time.Now().Format(time.RFC3339)
		planText := fmt.Sprintf("clientCode=%s&dateStr=%s&signSecret=%s", proxyConnOption.clientCode, currentDateStr, proxyConnOption.signSecret)
		signStr := Md5(planText)

		registerInfo := RegisterInfo{
			ClientCode: proxyConnOption.clientCode,
			DateStr:    currentDateStr,
			Sign:       signStr,
		}
		registerBodyBytes, marshalErr := json.Marshal(registerInfo)
		if marshalErr != nil {
			proxyConn.err = fmt.Errorf("%v", marshalErr)
			return
		}
		registerBodyLen := len(registerBodyBytes)
		registerBodyLenBytes := Int32ToByteBigEndian(int32(registerBodyLen))
		messageBytes := append(registerBodyLenBytes, registerBodyBytes...)
		_, err := conn.Write(messageBytes)
		if err != nil {
			proxyConn.err = fmt.Errorf("register error: %v", err)
			return
		}
		return
	}
	proxyConn.err = fmt.Errorf("unsupport encryptType: %d", proxyConnOption.encryptType)
	return
}

func newServerProxyConn(conn net.Conn, encryptType int, getClientCode func(clientCode string) (*ClientInfo, error)) (proxyConn *ProxyConn) {
	proxyConn = &ProxyConn{
		err:  nil,
		conn: conn,
		ProxyConnOption: ProxyConnOption{
			encryptType: encryptType,
			clientCode:  "",
			signSecret:  "",
			encryptKey:  nil,
		},
	}
	if encryptType == UnEncrypt {
		return
	}
	if encryptType == AES {
		dataLenBytes := make([]byte, 4)
		_, err := conn.Read(dataLenBytes)
		if err != nil {
			if err != io.EOF {
				proxyConn.err = fmt.Errorf("conn read message len error: %v", err)
				return
			}
		}
		dataLen := BigEndianToUint32(dataLenBytes)

		registerMaxLen := uint32(64 * 1024)
		if dataLen > registerMaxLen {
			proxyConn.err = fmt.Errorf("register message len too long: %d, max len: %d", dataLen, registerMaxLen)
			return
		}
		dataBodyBytes := make([]byte, 0)
		for {
			buffer := make([]byte, dataLen-uint32(len(dataBodyBytes)))
			n, readErr := conn.Read(buffer)
			if readErr != nil {
				if readErr != io.EOF {
					proxyConn.err = fmt.Errorf("conn read message body error: %v", readErr)
					return
				}
				break
			}

			dataBodyBytes = append(dataBodyBytes, buffer[:n]...)
			if uint32(len(dataBodyBytes)) == dataLen {
				break
			}
		}

		registerInfo := RegisterInfo{}
		err = json.Unmarshal(dataBodyBytes, &registerInfo)
		if err != nil {
			proxyConn.err = fmt.Errorf("unmarshal RegisterInfo error: %v", err)
			return
		}

		var clientInfo *ClientInfo
		if clientInfo, err = getClientCode(registerInfo.ClientCode); err != nil {
			proxyConn.err = fmt.Errorf("getClientCode error: %v", err)
			return
		}

		planText := fmt.Sprintf("clientCode=%s&dateStr=%s&signSecret=%s", registerInfo.ClientCode, registerInfo.DateStr, clientInfo.SignSecret)
		signStr := Md5(planText)
		if signStr != registerInfo.Sign {
			proxyConn.err = fmt.Errorf("sign: %s error", registerInfo.Sign)
			return
		}
		registerDate, parseErr := time.Parse(time.RFC3339, registerInfo.DateStr)
		if parseErr != nil {
			proxyConn.err = fmt.Errorf("parse register dateStr: %s error: %v", registerInfo.DateStr, parseErr)
			return
		}

		fgExpires := time.Since(registerDate) > 5*time.Minute
		if fgExpires {
			proxyConn.err = fmt.Errorf("dateStr: %s expires", registerInfo.DateStr)
			return
		}
		proxyConn.encryptType = encryptType
		proxyConn.clientCode = clientInfo.ClientCode
		proxyConn.signSecret = clientInfo.SignSecret
		proxyConn.encryptKey = []byte(clientInfo.Secret)
		return
	}
	proxyConn.err = fmt.Errorf("unsupport encryptType: %d", encryptType)
	return
}

// override net.Conn
func (pc *ProxyConn) Read(b []byte) (n int, err error) {
	if pc.err != nil {
		err = pc.err
		return
	}
	if pc.encryptType == UnEncrypt {
		return pc.conn.Read(b)
	}
	if pc.encryptType == AES {
		if len(pc.readbuf) >= len(b) {
			copy(b, pc.readbuf)
			pc.readbuf = pc.readbuf[len(b):]
			return len(b), nil
		}

		dataLenBytes := make([]byte, 4)
		_, err = pc.conn.Read(dataLenBytes)
		if err != nil {
			if err != io.EOF {
				err = fmt.Errorf("conn read message len error: %v", err)
				return
			}
		}
		dataLen := BigEndianToUint32(dataLenBytes)

		dataBodyBytes := make([]byte, 0)
		for {
			buffer := make([]byte, dataLen-uint32(len(dataBodyBytes)))
			var readLen int
			readLen, err = pc.conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					err = fmt.Errorf("conn read message body error: %v", err)
					return
				}
				break
			}

			dataBodyBytes = append(dataBodyBytes, buffer[:readLen]...)
			if uint32(len(dataBodyBytes)) == dataLen {
				break
			}
		}

		plainBytes, decyptErr := DecryptAES(pc.encryptKey, dataBodyBytes)
		if decyptErr != nil {
			err = fmt.Errorf("DecryptAES message body error: %v", decyptErr)
			return
		}

		copy(b, plainBytes)
		return len(plainBytes), nil
	}
	return 0, fmt.Errorf("unsupport encryptType: %d", pc.encryptType)
}

// override net.Conn
func (pc *ProxyConn) Write(b []byte) (n int, err error) {
	if pc.err != nil {
		err = pc.err
		return
	}
	if pc.encryptType == UnEncrypt {
		return pc.conn.Write(b)
	}
	if pc.encryptType == AES {
		encryptMessageBytes, encryptErr := EncryptAES(pc.encryptKey, b)
		if encryptErr != nil {
			err = fmt.Errorf("EncryptAES error: %v", encryptErr)
			return
		}
		encryptMessageLen := len(encryptMessageBytes)
		encryptMessageLenBytes := Int32ToByteBigEndian(int32(encryptMessageLen))
		fullMessageBytes := append(encryptMessageLenBytes, encryptMessageBytes...)
		_, err = pc.conn.Write(fullMessageBytes)
		if err != nil {
			err = fmt.Errorf("register error: %v", err)
			return
		}
		return len(b), nil
	}
	return 0, fmt.Errorf("unsupport encryptType: %d", pc.encryptType)
}

// override net.Conn
func (pc *ProxyConn) Close() error {
	return pc.conn.Close()
}

// override net.Conn
func (pc *ProxyConn) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

// override net.Conn
func (pc *ProxyConn) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr()
}

// override net.Conn
func (pc *ProxyConn) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

// override net.Conn
func (pc *ProxyConn) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

// override net.Conn
func (pc *ProxyConn) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}
