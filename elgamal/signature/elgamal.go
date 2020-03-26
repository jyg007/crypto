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
   fmt.Println(ED25519.CURVETYPE)
   
   rnd := GetRand()

   // private and public keys of the signers
   x := RandModOrder(rnd)
   Y := GenG.Mul(x)

 // fmt.Println(sk)
   //fmt.Println(pk)

//fmt.Println("public key",EcpToBytes(hECP))

  k := RandModOrder(rnd)
  R := GenG.Mul(k)    

/*
   msg := ED25519.FromBytes([]byte("Hello World"))
   fmt.Print(msg)
*/
  // faire le sha(256) de r.ToBytes() + msg
	 M:=sha256.New()
 // H.Write([]byte(EcpToBytes(r)))
   M.Write([]byte("Hello World"))
	 hash := M.Sum(nil) 

    h := ED25519.FromBytes(hash[:])
    h.Mod(GroupOrder)


    r := R.GetX()
 //  r.Mod(GroupOrder)

   
   /*
    xr := ED25519.Modmul(r,x,GroupOrder)
    p1 := ED25519.Modadd(h,xr,GroupOrder)
    k.Invmodp(GroupOrder)
    s := ED25519.Modmul(k,p1,GroupOrder)
*/

   xr := ED25519.Modmul(x,r,GroupOrder)
   p1 := Modsub(h,xr,GroupOrder)

   k.Invmodp(GroupOrder)
   s := ED25519.Modmul(p1,k,GroupOrder)
  
  

    fmt.Println(R.ToString())
    fmt.Println(s.ToString())



    //Checking Verify

    GHM := GenG.Mul(h)
    YRRS := Y.Mul2(r,R,s)
    fmt.Println(YRRS.ToString())
    fmt.Println(GHM.ToString())


/*
      V2 := GenG.Mul(h)
      V1 := R.Mul(s)
      rA := Y.Mul(r)
      V2.Add(rA)

      fmt.Println(V1.ToString())
      fmt.Println(V2.ToString())
*/


}
