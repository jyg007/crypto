package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
//	 b64 "encoding/base64"
	//"os"
//	"strconv"
	"crypto/rand"
	amcl "github.com/miracl/core/go/core"
	curve "github.com/miracl/core/go/core/BLS48581"
//	"golang.org/x/crypto/sha3"
)

var GenG1 = curve.ECP_generator()
var GenG2 = curve.ECP8_generator()

// GenGT is a generator of Group GT
var GenGT = curve.Fexp(curve.Ate(GenG2, GenG1))



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

func RandModOrder(rng *amcl.RAND) *curve.BIG {
	// curve order q
	q := curve.NewBIGints(curve.CURVE_Order)

	// Take random element in Zq
	return curve.Randomnum(q, rng)
}


func main() {

   // Key generation for the  3 parties
   rnd := GetRand()
   a:= RandModOrder(rnd)
   b:= RandModOrder(rnd)
   c:= RandModOrder(rnd)

   // Public info to shared
   //For A:
   Pa:=GenG2.Mul(a)
   fmt.Println("Public Key for A: ", Pa.ToString())

   Pb1:=GenG1.Mul(b)
   Pb2:=GenG2.Mul(b)
   fmt.Println("Public key1 for B:", Pb1.ToString()) 
   fmt.Println("Public key2 for B:",Pb2.ToString())


   Pc := GenG1.Mul(c)
   fmt.Println("Public key for C:" ,Pc.ToString())

  fmt.Println()
  //Key Sharing
  A := curve.Fexp(curve.Ate(Pb2,Pc)).Pow(a)
  B := curve.Fexp(curve.Ate(Pa,Pc)).Pow(b)
  C := curve.Fexp(curve.Ate(Pa,Pb1)).Pow(c)

  fmt.Println(A.ToString())
  fmt.Println(B.ToString())
  fmt.Println(C.ToString())

}