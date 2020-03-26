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
func Encrypt(A *ED25519.ECP, m int, rnd *amcl.RAND) ( *ED25519.ECP, *ED25519.ECP) {
  //Encryption with public
  k := RandModOrder(rnd)
  kA :=A.Mul(k)  

  K := GenG.Mul(k)


  Mbig := ED25519.NewBIGint(m)
  Mbig.Mod(GroupOrder)


  // funtion de map d un int à un point de la courbe G^n ... 
  M := GenG.Mul(Mbig)

  //fmt.Println("M",M.ToString())

  kA.Add(M) 

  C := ED25519.NewECP()

  C.Copy(kA)
  fmt.Println("C crypté",C.ToString())

  return K, C

}

// priv key du receiver en entrée
func Decrypt(a *ED25519.BIG, K *ED25519.ECP, C *ED25519.ECP, rnd *amcl.RAND) int {
   S := K.Mul(a)  
   CC := ED25519.NewECP()
   CC.Copy(C)

   CC.Sub(S)

 //  return C.ToString()
 //fmt.Println("C",C.ToString())
 
   // reverse mapping, point de courbe sur un entier
    Mc := ED25519.NewECP()

    Mi := ED25519.NewBIGint(0)
    Mc = GenG.Mul(Mi)
    i:=0

	for    !Mc.Equals(CC)  && i < 100{
  	//	 fmt.Println(i," ",Mc.ToString())
  		 Mc.Add(GenG)
  		 i++
	}
	return i

}


func main() {
	/*

  Abig := ED25519.NewBIGint(1050)
  Abig.Mod(GroupOrder)

  AA := ED25519.NewECPbig(Abig)

  Bbig := ED25519.NewBIGint(1050)
  Bbig.Mod(GroupOrder)

  BB := ED25519.NewECPbig(Bbig)

  AA.Add(BB)

  fmt.Println(AA.ToString())
*/
   
   rnd := GetRand()

   // private and public keys for Alice 
   a := RandModOrder(rnd)
   A := GenG.Mul(a)

   K := ED25519.NewECP()
   K1 := ED25519.NewECP()
   K2 := ED25519.NewECP()
   C := ED25519.NewECP()
   C1 := ED25519.NewECP()
   C2 := ED25519.NewECP()
   var u int
   

   K1, C1 = Encrypt(A,10,rnd)
   u = Decrypt(a, K1,C1,rnd)
   fmt.Print("en clair " ,u,"\n\n")

   K2, C2 = Encrypt(A,10,rnd)
   u = Decrypt(a, K2,C2,rnd)
   fmt.Print("en clair ",u,"\n\n")


   // Test de l addition homorphisme sur donnée crypté
   K1.Add(K2)
   C1.Add(C2)
   fmt.Println("addition crypté ",C1.ToString())
   u = Decrypt(a, K1,C1,rnd)
   fmt.Print(u,"\n\n")


   K, C = Encrypt(A,20,rnd)
   u = Decrypt(a, K,C,rnd)
   fmt.Print(u,"\n\n")
  // maintenant pour prouver que cela est 20 il faut faire en brute force en sens inverse

/*

   // reverse mapping, point de courbe sur un entier
    Mc := ED25519.NewECP()

    Mi := ED25519.NewBIGint(0)
        Mc = GenG.Mul(Mi)
	for i := 0; i < 15; i++ {
  		 fmt.Println(i," ",Mc.ToString())
  		 Mc.Add(GenG)
	}
*/
}
