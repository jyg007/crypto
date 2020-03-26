package main

import (
	"fmt"
	"crypto/rand"
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

   // private and public keys of the signers
   x := RandModOrder(rnd)
   H := GenG.Mul(x)

  //Encryption with public key H
  y := RandModOrder(rnd)
  S :=H.Mul(y)  

  fmt.Println("S",S.GetX().ToString())  
  C1 := GenG.Mul(y)


  msg := make([]byte,ED25519.MODBYTES)
    m := "Bonjour cest"

  mm := msg[ED25519.MODBYTES-uint(len(m)):]


  copy(mm,[]byte(m))
  //msg[0] = 2
  fmt.Println(msg)

  Mbig := ED25519.FromBytes(msg)
  Mbig.Mod(GroupOrder)

  M := ED25519.NewECPbig(Mbig)

  fmt.Println("M",Mbig.ToString())

  C2x := ED25519.Modmul(M.GetX(),S.GetX(), GroupOrder)
  C2y := ED25519.Modmul(M.GetY(),S.GetY(), GroupOrder)

fmt.Println("C2X: ", C2x.ToString())

 // C2 := ED25519.NewECPbigs(C2x,C2y)

  //fmt.Println(C1.ToString())
  //fmt.Println(C2.ToString())



   //Decryption with private Key x

   S2 := C1.Mul(x) 
   S2x := S2.GetX()
   S2y := S2.GetY()
   //fmt.Println("S2",S.GetX().ToString())  

   S2x.Invmodp(GroupOrder)
   S2y.Invmodp(GroupOrder)

    
   M1 := ED25519.Modmul(C2x,S2x,GroupOrder)
   M2 := ED25519.Modmul(C2y,S2y,GroupOrder)
   
   MM := ED25519.NewECPbigs(M1,M2)

   b := make([]byte,ED25519.MODBYTES)

   M1.ToBytes(b)
   fmt.Println(string(b))
   fmt.Println(M1.ToString())
   fmt.Println(MM.GetY().ToString())

}
