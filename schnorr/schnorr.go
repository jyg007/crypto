package main

import (
	"fmt"
	"crypto/rand"
	"crypto/sha256"
	amcl "github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/ED25519"
)
// FieldBytes is the bytelength of the group order
var FieldBytes = int(ED25519.MODBYTES)


func EcpToBytes(E *ED25519.ECP) []byte {
	length := 2*FieldBytes + 1
	res := make([]byte, length)
	E.ToBytes(res, false)
	return res
}

// Modsub takes input BIGs a, b, m and returns a-b modulo m
func Modsub(a, b, m *ED25519.BIG) *ED25519.BIG {
	return Modadd(a, ED25519.Modneg(b, m), m)
}

// Modadd takes input BIGs a, b, m, and returns a+b modulo m
func Modadd(a, b, m *ED25519.BIG) *ED25519.BIG {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

var GenG = ED25519.NewECPbigs(
	ED25519.NewBIGints(ED25519.CURVE_Gx),
	ED25519.NewBIGints(ED25519.CURVE_Gy))

// GetRand returns a new *amcl.RAND with a fresh seed
func GetRand() (*amcl.RAND) {
	seedLength := 32
	b := make([]byte, seedLength)
	_, err := rand.Read(b)
	if err != nil {
		 fmt.Print(err ,"error getting randomness for seed")
		 return nil
	}
	rng := amcl.NewRAND()
	rng.Clean()
	rng.Seed(seedLength, b)
	return rng
}

func RandModOrder(rng *amcl.RAND) *ED25519.BIG {
	// curve order q
	q := ED25519.NewBIGints(ED25519.CURVE_Order)

	// Take random element in Zq
	return ED25519.Randomnum(q, rng)
}

// GroupOrder is the order of the groups
var GroupOrder = ED25519.NewBIGints(ED25519.CURVE_Order)

func main() {
   
   rnd := GetRand()

   sk := RandModOrder(rnd)
   pk := GenG.Mul(sk)

   fmt.Println("sk ",sk.ToString())
   fmt.Println("pk ",pk.ToString())



   k := RandModOrder(rnd)
   r := GenG.Mul(k)
   // fmt.Println("r",r.ToString())
    
/*
   msg := ED25519.FromBytes([]byte("Hello World"))
   fmt.Print(msg)
*/
  // faire le sha(256) de r.ToBytes() + msg
	H:=sha256.New()
  H.Write([]byte(EcpToBytes(r)))
  H.Write([]byte("Hello World"))
	hash :=H.Sum(nil) 

    HBIG := ED25519.FromBytes(hash[:])
    HBIG.Mod(GroupOrder)
    

    fmt.Println()
    fmt.Println("sender")
    fmt.Println("e",HBIG.ToString())

    xe := ED25519.Modmul(sk,HBIG,GroupOrder)
    s := Modsub(k,xe,GroupOrder)

    fmt.Println("s",s.ToString())


    //Checking
    fmt.Println("\nReceiver")

    rv := pk.Mul2(HBIG,GenG,s)
    /*
    ye := pk.Mul(HBIG)
    gs := GenG.Mul(s)

    gs.Add(ye)

    fmt.Println("rv",gs)
    */
    fmt.Println("rv",rv.ToString())
    Hc:=sha256.New()
    Hc.Write([]byte(EcpToBytes(rv)))
    Hc.Write([]byte("Hello World"))
	  hashc :=Hc.Sum(nil) 

    HcBIG := ED25519.FromBytes(hashc[:])
    HcBIG.Mod(GroupOrder)
    
    fmt.Println("preuve: ev=e")
    fmt.Println("ev",HcBIG.ToString())


}
