package main

import (
	"fmt"
  "encoding/hex"
	"crypto/rand"
  "crypto/aes"
  "golang.org/x/crypto/sha3"
	amcl "github.com/miracl/core/go/core"
	curve "github.com/miracl/core/go/core/ED25519"
)
// FieldBytes is the bytelength of the group order
var FieldBytes = int(curve.MODBYTES)


func EcpToBytes(E *curve.ECP) []byte {
	length := 2*FieldBytes + 1
	res := make([]byte, length)
	E.ToBytes(res, false)
	return res
}

// Modsub takes input BIGs a, b, m and returns a-b modulo m
func Modsub(a, b, m *curve.BIG) *curve.BIG {
	return Modadd(a, curve.Modneg(b, m), m)
}

// Modadd takes input BIGs a, b, m, and returns a+b modulo m
func Modadd(a, b, m *curve.BIG) *curve.BIG {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

var GenG = curve.ECP_generator()

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

// GroupOrder is the order of the groups
var GroupOrder = curve.NewBIGints(curve.CURVE_Order)


func H(a *curve.ECP, b *curve.ECP ) ([]byte) {
   
  aAsBytes := EcpToBytes(a)
  bAsBytes := EcpToBytes(b) 

  hAsBytes := make([]byte,32)   //32 pour générer une clé AES-256

  hash:=sha3.NewShake256()
  hash.Write(aAsBytes)
  hash.Write(bAsBytes)
  hash.Read(hAsBytes)
  return hAsBytes
}

// Pub key H du receiver en entrée
func Encrypt(h *curve.ECP, m []byte , rnd *amcl.RAND) ( *curve.ECP, []byte) {
  //Encryption with public
  b := RandModOrder(rnd)
  V:=h.Mul(b)  

  U := GenG.Mul(b)

  k:=H(U,V)

  
   cy, err := aes.NewCipher(k)  
   if err != nil {  
      fmt.Errorf("NewCipher(%d bytes) = %s", len(k), err)  
      panic(err)  
   }  
   c := make([]byte, len(m))  
   cy.Encrypt(c, m)  

   return U, c

}

// priv key du receiver en entrée
func Decrypt(a *curve.BIG, U *curve.ECP, c []byte) []byte {
   V := U.Mul(a) 

   k:=H(U,V)
   
  // ciphertext, _ := hex.DecodeString(ct)  
   cy, err := aes.NewCipher(k)  
   if err != nil {  
      fmt.Errorf("NewCipher(%d bytes) = %s", len(k), err)  
      panic(err)  
   }  
   plain := make([]byte, len(c))  
   cy.Decrypt(plain, c)  
   //fmt.Printf("AES Decrypyed Text:  %s\n", string(plain) )
   

   return plain
}


func main() {
   
   rnd := GetRand()

   // private and public keys for Alice  (a,A)

   a := RandModOrder(rnd)
   A := GenG.Mul(a)

   MSG:="Comment allez vous"


  //encryption, utilisation de A uniquement
  u_AsECP, C_AsBytes := Encrypt(A,[]byte(MSG),rnd)

  u_AsHex := hex.EncodeToString(EcpToBytes(u_AsECP))
  C_AsHex := hex.EncodeToString(C_AsBytes)

  fmt.Println()
  fmt.Println("u:",u_AsHex)
  fmt.Println("C:",C_AsHex)
  fmt.Println()
 

  //decryption en utilisation C <U,V,W> et a
 
  tmp,_ := hex.DecodeString(u_AsHex)
  u_AsECP_dec := curve.ECP_fromBytes(tmp)
  C_AsBytes_dec, _ := hex.DecodeString(C_AsHex)

   m := Decrypt(a, u_AsECP_dec, C_AsBytes_dec)
   fmt.Print("decrypted :=> " ,string(m)+"\n\n")


}
