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

// BigToBytes takes an *amcl.BIG and returns a []byte representation
func BigToBytes(big *ED25519.BIG) []byte {
  ret := make([]byte, FieldBytes)
  big.ToBytes(ret)
  return ret
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


// X est l aggregated key representant chacun des signers, il est noté ~X dans le papier https://eprint.iacr.org/2018/068.pdf
// il peut être utilisé pour representer le compte
func GetX_AggregatedPk(pk1 *ED25519.ECP,pk2 *ED25519.ECP )(*ED25519.ECP, *ED25519.BIG,*ED25519.BIG ) {

   //Now we have X = summation of every participants H(L,P)P  - a=H(L,P)
   
    //L = H(set of each individual’s Public key P).
    Lhash:=sha256.New()
    Lhash.Write([]byte(EcpToBytes(pk1)))
    Lhash.Write([]byte(EcpToBytes(pk2)))
    LBytes :=Lhash.Sum(nil) 

    hash1 := sha256.New()
    hash1.Write(LBytes)
    hash1.Write([]byte(EcpToBytes(pk1)))
    hash1Bytes :=hash1.Sum(nil) 

    a1 := ED25519.FromBytes(hash1Bytes[:])
    a1.Mod(GroupOrder)

    X := pk1.Mul(a1)

    hash2 := sha256.New()
    hash2.Write(LBytes)
    hash2.Write([]byte(EcpToBytes(pk2)))
    hash2Bytes :=hash2.Sum(nil) 

    a2 := ED25519.FromBytes(hash2Bytes[:])
    a2.Mod(GroupOrder)
    
    X.Add(pk2.Mul(a2))

   // fmt.Println("X: ",X.ToString())

   return X,a1,a2
}


func Sign_GetR_and_c(R1 *ED25519.ECP,R2 *ED25519.ECP,X *ED25519.ECP, z []byte)  (*ED25519.ECP, *ED25519.BIG ) {
 
   //Each individual chooses their own unique r and calculates their own unique R = rG and R(sum) is the summation of all R.
    Rsum := ED25519.NewECP()
    Rsum.Copy(R1)
    Rsum.Add(R2)


  //c also changes from BN equation. c = H(X, R(sum), z)*a. A new variable ‘a’ is introduced where each participant uses their unique public key to calculate a = H(L, P). So, c = H(X, R(sum), z)H(L, P).

   //H(X, R(sum), z)
   hash := sha256.New()
   hash.Write(EcpToBytes(X))
   hash.Write(EcpToBytes(Rsum))
   hash.Write(z)
   HXRzBytes := hash.Sum(nil)
   HXRzBIG := ED25519.FromBytes(HXRzBytes[:])

   return Rsum, HXRzBIG

}


func Sign_Get_s(HXRzBIG *ED25519.BIG, r *ED25519.BIG, a *ED25519.BIG, x *ED25519.BIG)  (*ED25519.BIG) {

   // Each individual now must calculate their own s = r + cx 

   //c = H(X, R(sum), z)*a
   c:= ED25519.Modmul(HXRzBIG,a,GroupOrder)
   // c cx
   cx := ED25519.Modmul(c,x,GroupOrder)
   // s = r + cx 
   s := ED25519.Modadd(cx,r,GroupOrder)
   return s

}


func Sign_Get_S(s1 *ED25519.BIG,s2 *ED25519.BIG) (*ED25519.BIG){ 
     return ED25519.Modadd(s1,s2,GroupOrder)
}


func Verify_MSIG(pk1 *ED25519.ECP, pk2 *ED25519.ECP, RSum *ED25519.ECP, SSum *ED25519.BIG, msg []byte) bool {

   X,_,_ := GetX_AggregatedPk(pk1,pk2)

   hash := sha256.New()
   hash.Write(EcpToBytes(X))
   hash.Write(EcpToBytes(RSum))
   hash.Write(msg)
   HXRzBytes := hash.Sum(nil)
   cBIG := ED25519.FromBytes(HXRzBytes[:])

   cX := X.Mul(cBIG)

   RSum.Add(cX)

   SSumG := ED25519.NewECP()
   SSumG = GenG.Mul(SSum)

   fmt.Println()
   fmt.Println(RSum.ToString())
   fmt.Println(SSumG.ToString())
   return RSum.Equals(SSumG)
}



func main() {
   
   rnd := GetRand()
   msg := "Hello"

   sk1 := RandModOrder(rnd)
   pk1 := GenG.Mul(sk1)
   fmt.Println("pk1: ",pk1.ToString())

   sk2 := RandModOrder(rnd)
   pk2 := GenG.Mul(sk2)
   fmt.Println("pk2: ",pk2.ToString())


   fmt.Println()

  // Generation des r pour chacun
   r1 := RandModOrder(rnd)
   r2 := RandModOrder(rnd)

   // envoi des R aux autres signatires avec ti=H(Ri) pour verification à reception
   R1 := GenG.Mul(r1)
   R2 := GenG.Mul(r2)


   X,a1,a2 := GetX_AggregatedPk(pk1,pk2)

   fmt.Println("addresse X aggrégée: ",X.ToString())

   fmt.Println("\n")

   // envoi des Ri aux autres signataires
   RSum, c := Sign_GetR_and_c(R1,R2, X, []byte(msg))

   s1 := Sign_Get_s(c, r1, a1, sk1)
   s2 := Sign_Get_s(c, r2, a2, sk2)

   // envoi des si aux autres signataures
   SSum :=  Sign_Get_S(s1,s2)


   fmt.Println("Multi Sig pour le message",msg)
   fmt.Println("Rsum: ", RSum.ToString())
   fmt.Println("Ssum: ", SSum.ToString())


   // Verification pour un membre
   // à partir des clés, on calcul les ai et la clé aggrege X
   fmt.Println("\n\nVérification par un des membres, il doit y avoir égalité")

   Verify_MSIG(pk1 , pk2 , RSum , SSum ,[]byte(msg))

}
