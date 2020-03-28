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


func Sign(sk *ED25519.BIG, msg []byte, rnd *amcl.RAND) ( *ED25519.BIG, *ED25519.BIG) {
   kBIG := RandModOrder(rnd)
   rECP := GenG.Mul(kBIG)
   // fmt.Println("r",r.ToString())
    

 // fmt.Print(msg)

  // faire le sha(256) de r.ToBytes() + msg
    H:=sha256.New()
    H.Write([]byte(EcpToBytes(rECP)))
    H.Write(msg)
    hash :=H.Sum(nil) 

    eBIG := ED25519.FromBytes(hash[:])
    eBIG.Mod(GroupOrder)
    
    xeBIG := ED25519.Modmul(sk,eBIG,GroupOrder)
    sBIG := Modsub(kBIG,xeBIG,GroupOrder)

    return eBIG, sBIG
}

func Verify(pk *ED25519.ECP, eSig *ED25519.BIG, sSig *ED25519.BIG,msg []byte,rnd *amcl.RAND)( *ED25519.BIG) {
 
    rv := pk.Mul2(eSig,GenG,sSig)
    /*
    fmt.Println("rv",gs)
    */

    Hc:=sha256.New()
    Hc.Write([]byte(EcpToBytes(rv)))
    Hc.Write(msg)
    hashc :=Hc.Sum(nil) 

    ev := ED25519.FromBytes(hashc[:])
    ev.Mod(GroupOrder)

    return ev
}



func main() {
   
   rnd := GetRand()

   sk := RandModOrder(rnd)
   pk := GenG.Mul(sk)

   fmt.Println("sk ",sk.ToString())
   fmt.Println("pk ",pk.ToString())

   e:=  ED25519.NewBIG()
   s:=  ED25519.NewBIG()

   ev:=  ED25519.NewBIG()

   msg := "Hello World"


   e,s = Sign(sk,[]byte(msg),rnd)

   fmt.Println("Signature du msg", msg)
   fmt.Println("e",e.ToString())
   fmt.Println("s",s.ToString())

   //Checking
   fmt.Println("\nReceiver")
   ev = Verify(pk, e,s, []byte(msg),rnd)
   fmt.Println("ev",ev.ToString())


}
