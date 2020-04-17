package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"math/big"
	"golang.org/x/crypto/sha3"
)

const LONGUEUR_KEY int = 16
var  bigOne *big.Int = big.NewInt(1)

func H1( a []byte , n *big.Int ) (*big.Int) {   
        h := make([]byte,LONGUEUR_KEY/8)

        hash:=sha3.NewShake256()
        hash.Write(a)
        hash.Read(h)
        d:=new(big.Int).SetBytes(h)
        n2 := new(big.Int).Mul(n,n)
        d.Mod(d,n2)
        return d
}


func F(g *big.Int, m1 *big.Int, m2 *big.Int, n *big.Int) (*big.Int) {
	n2 := new(big.Int).Mul(n,n)
	a2 := new(big.Int).Exp(m2,n,n2)
	a1 := new(big.Int).Exp(g,m1,n2)
	a1.Mul(a1,a2)
	return a1.Mod(a1,n2)
}

func ChameleonHash(h *big.Int, m *big.Int, r1 *big.Int, r2 *big.Int, n *big.Int) (*big.Int) {

	n2 := new(big.Int).Mul(n,n)

	tmpm := new(big.Int).Mul(m,n)

    tmpm.Add(tmpm,bigOne)

    h.Exp(h,r1,n2)
    r2.Exp(r2,n,n2)
    h.Mul(h,r2)
    h.Mod(h,n2)

    tmpm.Mul(tmpm,h)
    tmpm.Mod(tmpm,n2)
    return tmpm
}





//Fonction de Charmichael - https://en.wikipedia.org/wiki/Carmichael_function
// Pallier paper https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_16.pdf
// l(n) = lcm(p-1,q-1) car n = p.q  et (q-1).(p-1) = lcm(p-1,q-1).gcd(p-1,q-1)
func lambda( p *big.Int, q *big.Int) (*big.Int) {
	ptmp := new(big.Int).Sub(p,bigOne)
	qtmp := new(big.Int).Sub(q,bigOne)

	gcd := new(big.Int).GCD(nil,nil, ptmp ,qtmp)
	pq := new(big.Int).Mul(ptmp,qtmp)
	return pq.Div(pq,gcd)
}

// voir Pallier definition of function n 
func L( u *big.Int, n *big.Int) (*big.Int) {

	U := new(big.Int).Sub(u,bigOne)
	//fmt.Println(U.String())
	return U
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

	n := new(big.Int)
    n = miryanPrivateKey.PublicKey.N


	Label := []byte("ID: JeanYves, DESC: ceci est nntest")
	M := []byte("Hello salut la compagnie")

 //   h := H1(Label,n)
  // h := big.NewInt(3)
    la := lambda(p,q)
    n2 := new(big.Int).Mul(n,n)
    h := new(big.Int)
    h = H1(Label,n)
    var az int64
    for az =1; ; az++ {
    	
    	h.Add(h,bigOne)

  //  fmt.Println("\np",p)
  //  fmt.Println("\nq",q)

   // fmt.Println("\nla",la,"\n")

        hlamba := new(big.Int).Exp(h,la,n2)
        i := new(big.Int).ModInverse(L(hlamba,n),n)
        if (i!= nil) {
        //	fmt.Println("h:",h)
        	break
        }	

    }
	fmt.Println("h:",h)

    m := H1(M,n)

    r1 ,_ := rand.Int(rand.Reader, n)
 	r2 ,_:= rand.Int(rand.Reader, n)

 	C := ChameleonHash(h,m,r1,r2,n)



	//fmt.Println("Hash(",string(Label),",",string(M),",",r1,",",r2,")\n\n",C.String())
	fmt.Println("C1",C.String())
	
	//mPrime := []byte("blablabla je vais tout masquer")

//    n2 := new(big.Int).Mul(n,n)

	Mprime := []byte("Et c est reparti pour une autre aventure")
	mprime := H1(Mprime,n)
	mprime.Mul(mprime,n)
	Cprime := new(big.Int).Sub(bigOne,mprime)
	Cprime.Mul(C,Cprime)
	Cprime.Mod(Cprime,n2)


	fmt.Println("cprime:",Cprime.String())

 //   la := lambda(p,q)
  //  fmt.Println("\np",p)
  //  fmt.Println("\nq",q)

   // fmt.Println("\nla",la,"\n")

    hlamba := new(big.Int).Exp(h,la,n2)
    cprimelanda := new(big.Int).Exp(Cprime,la,n2)
    fmt.Println("c'",cprimelanda," L ",L(cprimelanda,n)	)
    fmt.Println("h",hlamba," L ",L(hlamba,n)	)
    
  //   bigNegOne := new(big.Int).Neg(bigOne)

    i := new(big.Int).ModInverse(L(hlamba,n),n)
    fmt.Println("i:",i)

    m1 := new(big.Int).Mul(L(cprimelanda,n),i)
    m1.Mod(m1,n)

    fmt.Println(m1.String())
    m2neg := new(big.Int).Neg(m1)
    c2 := new(big.Int).Exp(h,m2neg,n)
    c2.Mul(c2,Cprime)
  //  c2.Mod(c2,n)

     //bigNegOne := new(big.Int).Neg(bigOne)
     ntmp := new(big.Int).ModInverse(n,la)
      fmt.Println("i:",ntmp)
     m2 := new(big.Int).Exp(c2,ntmp,n)



    // doit normalement être égal à Cprime
	fmt.Println("check avec CPrime:",F(h,m1,m2,n))
    


    fmt.Println()
    mp := H1(Mprime,n)
    C2  := ChameleonHash(h,mp,m1,m2,n)
	fmt.Println("C2",C2.String())
	

}
