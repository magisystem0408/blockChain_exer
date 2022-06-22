package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

type Wallet struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewWallet() *Wallet {
	w := new(Wallet)
	//privateKeyを作成
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//プライベートを格納
	w.privateKey = privateKey

	w.publicKey = &w.privateKey.PublicKey
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
