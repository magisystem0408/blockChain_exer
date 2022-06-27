package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type Wallet struct {
	privateKey        *ecdsa.PrivateKey
	publicKey         *ecdsa.PublicKey
	blockchainAddress string
}

func NewWallet() *Wallet {
	w := new(Wallet)
	//privateKeyを作成
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//プライベートを格納
	w.privateKey = privateKey
	w.publicKey = &w.privateKey.PublicKey

	//2 sha256でhash化する
	h2 := sha256.New()
	h2.Write(w.publicKey.X.Bytes())
	h2.Write(w.publicKey.Y.Bytes())
	digest2 := h2.Sum(nil)

	//3 RIPEMD-160 hash(20byte)
	h3 := ripemd160.New()
	h3.Write(digest2)
	digest3 := h3.Sum(nil)

	//4 byte をRIPEMD-160の前におく(0x00をつけくわえる。)
	vd4 := make([]byte, 21)
	vd4[0] = 0x00
	//21byteのバージョンバイトが生成される
	copy(vd4[1:], digest3[:])
	// sha256をhash化
	h5 := sha256.New()
	h5.Write(vd4)
	digest6 := h5.Sum(nil)
	// digetst5の初めの4byteをchecksumとしてしようする
	chsum := digest6[:4]
	dc8 := make([]byte, 25)
	copy(dc8[:21], vd4[:])
	copy(dc8[21:], chsum[:])

	//base58のエンコードを行う
	address := base58.Encode(dc8)
	w.blockchainAddress = address
	return w
}

//取り出せるようにする
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.privateKey
}

func (w *Wallet) PrivateKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

func (w *Wallet) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}

func (w *Wallet) PublicKeyStr() string {
	return fmt.Sprintf("%x%x", w.publicKey.X, w.publicKey.Y.Bytes())
}

func (w *Wallet) BlockchainAddress() string {
	return w.blockchainAddress
}
