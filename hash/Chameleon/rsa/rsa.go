package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"math/big"
	"golang.org/x/crypto/sha3"
)

const LONGUEUR_KEY int = 2048

func H1( a []byte  ) (*big.Int) {   
        h := make([]byte,LONGUEUR_KEY/8)

        hash:=sha3.NewShake256()
        hash.Write(a)
        hash.Read(h)
        d:=new(big.Int).SetBytes(h)
        return d
}

func ChameleonHash(h *big.Int, m *big.Int, r1 *big.Int, r2 *big.Int, n *big.Int,n2 *big.Int) (*big.Int) {

    h.Exp(h,r1,n2)

    r2.Exp(r2,n,n2)
    h.Mul(h,r2)
    h.Mod(h,n2)

    m.Mul(m,h)
    m.Mod(m,n2)
    return m
}



func main() {

	// Generate RSA Keys
	miryanPrivateKey, err := rsa.GenerateKey(rand.Reader, LONGUEUR_KEY)

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

//	miryanPublicKey := &miryanPrivateKey.PublicKey

	p := miryanPrivateKey.Primes[0]
	q := miryanPrivateKey.Primes[1]
	bigOne := big.NewInt(1)


	if (p.ProbablyPrime(5)) {
		fmt.Println("p est premier")
	}
	if (q.ProbablyPrime(5)) {
		fmt.Println("q est premier")
	}

	n := new(big.Int)
	//l := len(miryanPrivateKey.PublicKey.N.Bytes())
	
//	n.Mul(p,q)
    n = miryanPrivateKey.PublicKey.N
	n2 := miryanPrivateKey.PublicKey.N
	n2.Mul(n2,n)

    //fmt.Println(miryanPrivateKey.PublicKey.N)
	//fmt.Println()
	//fmt.Println(n)

	//fmt.Println("Private Key : ", miryanPrivateKey.Primes[0].Bytes(),miryanPrivateKey.Primes[1],n)

	Label := []byte("ID: JeanYves, DESC: ceci est nntest")
	M := []byte("Hello salut la compagnie")


    h := H1(Label)
    m := H1(M)
    m.Mul(m,n)
    m.Add(m,bigOne)


  //  rnd := r.rand.New(r.rand.NewSource(time.Now().UnixNano()))


    r1 ,_ := rand.Int(rand.Reader, n)
 	r2 ,_:= rand.Int(rand.Reader, n)


 



	fmt.Println("Hash(",string(Label),",",string(M),",",ChameleonHash(h,m,r1,r2,n,n2).String())
	
	//mPrime := []byte("blablabla je vais tout masquer")




}
