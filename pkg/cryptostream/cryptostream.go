package cryptostream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
// 	block, err := aes.NewCipher(key)
// 	return newStream(block, err, key, iv, doe)
// }

// var cipherMethod = map[string]*cipherInfo{
// 	"aes": {16, 16, newAESStream, newAESCFBStream},
// 	"des": {24, 16, newAESCFBStream, newAESCFBStream},
// }
func getCyptoParas(method_in string, key []byte, iv []byte) (method string, blocksize int, mode string, keyout []byte, err error) {
	tmp := strings.Split(method_in, "-")
	stackbuf := [128]byte{}
	method = tmp[0]
	blocksize = 16
	mode = "cfb"

	switch len(tmp) {

	case 1:
		break
	case 2:
		mode = tmp[1]
		break
	case 3:
		sizeInbit, err2 := strconv.Atoi(tmp[1])
		if err != nil {
			err = err2
			return
		}
		blocksize = sizeInbit / 8
		mode = tmp[2]
		break
	default:
		err = fmt.Errorf("Wrong method format")
		return
	}
	//fix key size
	keyout = stackbuf[0:blocksize]
	copy(keyout, key)
	return
}

type CipherStream struct {
	stream2cipher io.ReadCloser
	streamcipher  cipher.Stream
	blocksize     int
}

func NewCipherStream(stream2cipher io.ReadCloser, method string, key []byte, iv []byte) (cryptostream *CipherStream, err error) {
	method, blocksize, mode, fixedkey, err := getCyptoParas(method, key, iv)
	if err != nil {
		return
	}
	var block cipher.Block
	switch method {
	case "aes":
		block, err = aes.NewCipher(fixedkey)
		break
	case "des":
		block, err = des.NewCipher(fixedkey)
		break
	default:
		return nil, fmt.Errorf("Not supported method")
	}
	cryptostream = new(CipherStream)
	cryptostream.blocksize = blocksize
	cryptostream.stream2cipher = stream2cipher
	switch mode {
	// case "ofb":
	// 	cryptostream.streamcipher = &cipher.NewOFB(block, iv)
	// case "cbc":
	// 	o := cipher.NewCBCEncrypter(block, iv)
	case "cfb":
		cryptostream.streamcipher = cipher.NewCFBEncrypter(block, iv)
	case "ctr":
		cryptostream.streamcipher = cipher.NewCTR(block, iv)
	default:
		return nil, fmt.Errorf("Not supported mode")

	}

	return cryptostream, nil
}
func (cs *CipherStream) Read(p []byte) (n int, err error) {

	return 0, fmt.Errorf("Do not use read interface use WriteTo instead")
}
func (cs *CipherStream) WriteTo(dstStream io.Writer) (n int64, err error) {
	writer := &cipher.StreamWriter{S: cs.streamcipher, W: dstStream}
	n, err = io.Copy(writer, cs.stream2cipher)
	return
}

func (cs *CipherStream) Close() error {
	return cs.stream2cipher.Close()
}

type DecipherStream struct {
	stream2decipher io.ReadCloser
	decipher        cipher.Stream
	blocksize       int
}

func NewDecipherStream(stream2decipher io.ReadCloser, method string, key []byte, iv []byte) (cryptostream *DecipherStream, err error) {
	method, blocksize, mode, fixedkey, err := getCyptoParas(method, key, iv)
	if err != nil {
		return
	}
	var block cipher.Block
	switch method {
	case "aes":
		block, err = aes.NewCipher(fixedkey)
		break
	case "des":
		block, err = des.NewCipher(fixedkey)
		break
	default:
		return nil, fmt.Errorf("Not supported method")
	}
	cryptostream = new(DecipherStream)
	cryptostream.blocksize = blocksize
	cryptostream.stream2decipher = stream2decipher
	switch mode {
	// case "ofb":
	// 	cryptostream.streamcipher = &cipher.NewOFB(block, iv)
	// case "cbc":
	// 	o := cipher.NewCBCEncrypter(block, iv)
	case "cfb":
		cryptostream.decipher = cipher.NewCFBDecrypter(block, iv)
	case "ctr":
		cryptostream.decipher = cipher.NewCTR(block, iv)
	default:
		return nil, fmt.Errorf("Not supported mode")

	}

	return cryptostream, nil
}
func (cs *DecipherStream) WriteTo(dstStream io.Writer) (n int64, err error) {
	writer := &cipher.StreamWriter{S: cs.decipher, W: dstStream}
	n, err = io.Copy(writer, cs.stream2decipher)
	return
}

func (cs *DecipherStream) Read(p []byte) (n int, err error) {

	return 0, fmt.Errorf("Do not use read interface use WriteTo instead")
}
func (cs *DecipherStream) Close() error {
	return cs.stream2decipher.Close()
}

type CryptoStream struct {
	upstream       io.ReadWriteCloser
	decipher       cipher.Stream
	cipher         cipher.Stream
	blocksize      int
	decipherstream cipher.StreamReader
	cipherstream   cipher.StreamWriter
}

func NewCryptoStream(upstream io.ReadWriteCloser, method string, key []byte, iv []byte) (cryptostream *CryptoStream, err error) {
	method, blocksize, mode, fixedkey, err := getCyptoParas(method, key, iv)
	if err != nil {
		return
	}
	var block cipher.Block
	switch method {
	case "aes":
		block, err = aes.NewCipher(fixedkey)
		break
	case "des":
		block, err = des.NewCipher(fixedkey)
		break
	default:
		return nil, fmt.Errorf("Not supported method")
	}
	cryptostream = new(CryptoStream)
	cryptostream.blocksize = blocksize
	cryptostream.upstream = upstream

	switch mode {
	// case "ofb":
	// 	cryptostream.cipherstream = cipher.NewOFB(block, iv)
	// case "cbc":
	// 	o := cipher.NewCBCEncrypter(block, iv)
	case "cfb":
		cryptostream.decipher = cipher.NewCFBDecrypter(block, iv)
		cryptostream.cipher = cipher.NewCFBEncrypter(block, iv)
	case "ctr":
		cryptostream.decipher = cipher.NewCTR(block, iv)
		cryptostream.cipher = cipher.NewCTR(block, iv)
	default:
		return nil, fmt.Errorf("Not supported mode")

	}
	cryptostream.decipherstream.S = cryptostream.decipher // = cipher.StreamReader{S: , R: cryptostream.upstream}
	cryptostream.decipherstream.R = cryptostream.upstream
	cryptostream.cipherstream.S = cryptostream.cipher //= cipher.StreamWriter{S: , W: }
	cryptostream.cipherstream.W = cryptostream.upstream
	return cryptostream, nil
}

// func (cs *CryptoStream) WriteTo(dstStream io.Writer) (n int64, err error) {
// 	n, err = io.Copy(dstStream, cs.decipherstream)
// 	return
// }

// func (cs *CryptoStream) ReadFrom(srcStream io.Reader) (n int64, err error) {
// 	return io.Copy(cs.cipherstream, srcStream)

// }
func (cs *CryptoStream) Write(p []byte) (n int, err error) {
	return cs.cipherstream.Write(p)

}
func (cs *CryptoStream) Read(p []byte) (n int, err error) {

	return cs.decipherstream.Read(p)
}

func (cs *CryptoStream) Close() error {
	return cs.upstream.Close()
}
