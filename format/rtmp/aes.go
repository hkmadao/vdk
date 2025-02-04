package rtmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

func EncryptAES(key []byte, plainBytes []byte) (bytes []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// The IV needs to be unique, but does not have to be secret.
	// You can calculate it once with the key and keep it with the ciphertext.
	iv := key[:block.BlockSize()]

	stream := cipher.NewOFB(block, iv)

	bytes = make([]byte, len(plainBytes))
	stream.XORKeyStream(bytes, plainBytes)

	return
}

func DecryptAES(key []byte, encrypted []byte) (bytes []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv := key[:block.BlockSize()]

	stream := cipher.NewOFB(block, iv)

	bytes = make([]byte, len(encrypted))
	stream.XORKeyStream(bytes, encrypted)

	return
}

func Int32ToByteBigEndian(number int32) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte(number >> (3 * 8))
	bytes[1] = byte(number >> (2 * 8))
	bytes[2] = byte(number >> (1 * 8))
	bytes[3] = byte(number)

	return bytes
}

func BigEndianToUint32(bytes []byte) (dataLen uint32) {
	dataLen = binary.BigEndian.Uint32(bytes)
	return
}

func Md5(unMd5Str string) (md5Str string) {
	md5Str = fmt.Sprintf("%x", md5.Sum([]byte(unMd5Str)))
	return
}
