package hdwallet

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

func (w *Wallet) DerivePrivateKey(path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	return w.derivePrivateKey(path)
}

func GenNewMnemonic128() string {
	return GenNewMnemonic(128)
}

func GenNewMnemonic256() string {
	return GenNewMnemonic(256)
}

func GenNewMnemonic(bitSize int) string {
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		panic(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		panic(err)
	}

	return mnemonic
}

func DerivePrivateKeys(mnemonic string, startIndex int, length int) []string {
	wallet, err := NewFromMnemonic(mnemonic)
	if err != nil {
		panic(err)
	}

	privs := make([]string, length)

	for i := 0; i < 1000; i++ {
		pathStr := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		path := MustParseDerivationPath(pathStr)
		privEcdsa, err := wallet.DerivePrivateKey(path)
		if err != nil {
			panic(err)
		}
		privs[i] = ecdsaPrivateKeyToHex(privEcdsa)
	}

	return privs
}

func ecdsaPrivateKeyToHex(prv *ecdsa.PrivateKey) string {
	src := crypto.FromECDSA(prv)
	b := make([]byte, len(src)*2)
	hex.Encode(b, src)
	return string(b)
}
