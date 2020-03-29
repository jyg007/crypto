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
func GetX_AggregatedPk(pk []*ED25519.ECP)(*ED25519.ECP, []*ED25519.BIG ) {
    n:= len(pk)
   //Now we have X = summation of every participants H(L,P)P  - a=H(L,P)
   
    a := make([]*ED25519.BIG,n)

    //L = H(set of each individual’s Public key P).
    Lhash:=sha256.New()
    for i := 0 ; i< n ; i++ {
          Lhash.Write([]byte(EcpToBytes(pk[i])))
    }
    LBytes :=Lhash.Sum(nil) 

    X := ED25519.NewECP()
    for i := 0 ; i< n ; i++ {
          hash1 := sha256.New()
          hash1.Write(LBytes)
          hash1.Write([]byte(EcpToBytes(pk[i])))
          hash1Bytes :=hash1.Sum(nil) 
          a[i] = ED25519.FromBytes(hash1Bytes[:])
          a[i].Mod(GroupOrder)
          if (i==0) {
                X = pk[i].Mul(a[i])
          } else {
                X.Add(pk[i].Mul(a[i]))
          }
    }

   // fmt.Println("X: ",X.ToString())

   return X,a
}


func Sign_GetR_and_c(R []*ED25519.ECP,X *ED25519.ECP, z []byte)  (*ED25519.ECP, *ED25519.BIG ) {
 
   //Each individual chooses their own unique r and calculates their own unique R = rG and R(sum) is the summation of all R.
    Rsum := ED25519.NewECP()
    Rsum.Copy(R[0])
    
    for i:=1; i< len(R); i++ {
          Rsum.Add(R[i])
    }

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


func Sign_Get_S(s []*ED25519.BIG) (*ED25519.BIG){ 
     Sum := ED25519.NewBIGcopy(s[0])
     for i:=1;i<len(s);i++ {
         Sum = ED25519.Modadd(Sum,s[i],GroupOrder)
     }
     return Sum
}


func Verify_MSIG(pk []*ED25519.ECP, RSum *ED25519.ECP, SSum *ED25519.BIG, msg []byte) bool {

   X,_ := GetX_AggregatedPk(pk)

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

   n:= 30
   var i int

   sk := make([]*ED25519.BIG,n)
   pk := make([]*ED25519.ECP,n)

   for i=0;i<n;i++ {
      sk[i] = ED25519.NewBIG()
      sk[i] = RandModOrder(rnd)
      pk[i] = ED25519.NewECP()
      pk[i] = GenG.Mul(sk[i])
      fmt.Println("pk[",i,"]",pk[i].ToString())
   } 


   fmt.Println()

   r := make([]*ED25519.BIG,n)
   R := make([]*ED25519.ECP,n)

   for i=0;i<n;i++ {
      r[i] = ED25519.NewBIG()
      r[i] = RandModOrder(rnd)
      R[i] = ED25519.NewECP()
      R[i] = GenG.Mul(r[i])
   } 

   a := make([]*ED25519.BIG,n)

   X,a := GetX_AggregatedPk(pk)

   fmt.Println("addresse X aggrégée: ",X.ToString())

   fmt.Println("\n")

   // envoi des Ri aux autres signataires
   RSum, c := Sign_GetR_and_c(R, X, []byte(msg))


   s := make([]*ED25519.BIG,n)
   for i =0 ; i< n ; i++ {
      s[i] = Sign_Get_s(c, r[i], a[i], sk[i])
   }


   // envoi des si aux autres signataures
   SSum :=  Sign_Get_S(s)

   fmt.Println("Multi Sig pour le message",msg)
   fmt.Println("Rsum: ", RSum.ToString())
   fmt.Println("Ssum: ", SSum.ToString())

   // Verification pour un membre
   // à partir des clés, on calcul les ai et la clé aggrege X
   fmt.Println("\n\nVérification par un des membres, il doit y avoir égalité")

   Verify_MSIG(pk , RSum , SSum ,[]byte(msg))

}
