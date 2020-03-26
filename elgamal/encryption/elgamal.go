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

// Pub key du receiver en entrée
func Encrypt(A *ED25519.ECP, m string, rnd *amcl.RAND) ( *ED25519.ECP, *ED25519.ECP) {
  //Encryption with public
  k := RandModOrder(rnd)
  kA :=A.Mul(k)  

  K := GenG.Mul(k)

  //limitation à des blocks de 20 octets
  msg := make([]byte,ED25519.MODBYTES)
  mm := msg[ED25519.MODBYTES-uint(len(m)):]

  copy(mm,[]byte(m))
  //msg[0] = 2
  fmt.Println(mm)

  Mbig := ED25519.FromBytes(msg)
  Mbig.Mod(GroupOrder)

  M := ED25519.NewECPbig(Mbig)

  fmt.Println("M",M.ToString())

  kA.Add(M) 

  C := ED25519.NewECP()

  C.Copy(kA)
  fmt.Println("C crypté",C.ToString())

  return K, C

}

// priv key du receiver en entrée
func Decrypt(a *ED25519.BIG, K *ED25519.ECP, C *ED25519.ECP, rnd *amcl.RAND) []byte {
   S := K.Mul(a) 
   C.Sub(S)
   
   MDec := ED25519.NewECP()
   MDec.Copy(C)

   b := make([]byte,ED25519.MODBYTES)
   MDec.GetX().ToBytes(b)

   return b
}


func main() {
   
   rnd := GetRand()

   // private and public keys for Alice 
   a := RandModOrder(rnd)
   A := GenG.Mul(a)

   K := ED25519.NewECP()
   C := ED25519.NewECP()
   var u []byte 
   

   K, C = Encrypt(A,"Wlobabubli",rnd)
   u = Decrypt(a, K,C,rnd)
   fmt.Print(string(u)+"\n\n")


}
