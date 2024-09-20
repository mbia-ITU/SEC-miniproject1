package main

import (
	"flag"
	"fmt"
	"math/big"
)

const (
	Base  int64 = 666
	Prime int64 = 6661
)

func main() {
	smsg := flag.Int64("n", 0, "Enter secret message (integers only):")
	flag.Parse()
	bobPKey := big.NewInt(2227)

	alicePKey, msgc := elgamelEncrypt(*big.NewInt(*smsg), *bobPKey, *big.NewInt(2000))
	fmt.Printf("Public key: %s, Message: %s\n", alicePKey.Text(10), msgc.Text(10))

	bobSecret, msg := interceptmsg(*bobPKey, *alicePKey, *msgc)
	fmt.Printf("Secret is: %s, Message is: %s\n", bobSecret.Text(10), msg.Text(10))

	modifiedmsgc := big.NewInt(6000)
	bobMsg := elgamelDecrypt(bobSecret, *alicePKey, *modifiedmsgc)
	fmt.Printf("Tampered message: %s\n", bobMsg.Text(10))
}

func findKey(base, prime, s big.Int) *big.Int {

	result := big.NewInt(0)
	result.Exp(&base, &s, nil)
	result.Mod(result, &prime)
	return result
}

func elgamelEncrypt(sKey, pKey, msg big.Int) (key, c *big.Int) {
	sBase := big.NewInt(Base)
	sPrime := big.NewInt(Prime)

	smsg := findKey(*sBase, *sPrime, sKey)
	cKey := findKey(pKey, *sPrime, sKey)
	c = big.NewInt(0)
	c.Mul(cKey, &msg)

	return smsg, c

}

func elgamelDecrypt(smsg, pKey, c big.Int) big.Int {
	sKey := findKey(pKey, *big.NewInt(Prime), smsg)
	result := big.NewInt(0)
	return *result.Div(&c, sKey)
}

func interceptmsg(target, pKey, c big.Int) (s, msg big.Int) {
	base := big.NewInt(Base)
	prime := big.NewInt(Prime)
	i := big.NewInt(1)
	var limiter big.Int = *big.NewInt(1000)

	for k := *big.NewInt(1); k.Cmp(&limiter) < 0; k.Add(&k, i) {
		key := findKey(*base, *prime, k)

		if key.Cmp(&target) == 0 {
			msg := elgamelDecrypt(k, pKey, c)
			return k, msg
		}
	}
	return *big.NewInt(0), *big.NewInt(0)
}
