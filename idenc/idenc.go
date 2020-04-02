package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	 b64 "encoding/base64"
	//"os"
//	"strconv"
	"crypto/rand"
	amcl "github.com/miracl/core/go/core"
	curve "github.com/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
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



// nh longueur du hash à generer qui depend ici de la longueur du message. 
// hash de Gt vers {0,1}^m

func H2(n *curve.FP48 , nh int) ([]byte) {
    // FP48 a 3 FP16 qui a 2 FP8 qui 2 FP4 qui 2 FP2 qui 2 FP
	nn := make([]byte,int(3*2*2*2*2*(curve.MODBYTES)))    
	n.ToBytes(nn)

	h := make([]byte,nh)

	hash:=sha3.NewShake256()
	hash.Write(nn)
	hash.Read(h)
	return h
}

func xor( s1 []byte, s2 []byte) ([]byte) {
	s := make([]byte,len(s1))
	for i := 0 ; i < len(s1); i++ {
		s[i] = s1[i]^s2[i]
	}
	return s
}





func main() {
    msg := "Bonjour comment allez vous"

	//initialization de la master key pour la central authority
   rnd := GetRand()
   s := RandModOrder(rnd)
   Ppub := GenG2.Mul(s)


   //key generation, envoi d un fichier à jeanyves.girard@fr.ibm.com
   ida := "jeanyves.girard@fr.ibm.com"
   Pa:=curve.ECP_mapit([]byte(ida))
   Sa := Pa.Mul(s)

   // Encryption avec la clé publique
   l := RandModOrder(rnd)
   R := GenG2.Mul(l)
   h2 := H2(curve.Fexp(curve.Ate(Ppub,Pa)).Pow(l),len(msg))

   c:= xor(h2,[]byte(msg))

   fmt.Println("R=> ", R. ToString())
   fmt.Println("c=> ",b64.StdEncoding.EncodeToString(xor(c,[]byte(msg))))

   c_b64 := b64.StdEncoding.EncodeToString(xor(h2,[]byte(msg)))
   // ce serait de le padding pour eviter de savoir le nombre de lettre ds le message



   //decryption avec ma clé privé

   c_decoded , _ := b64.StdEncoding.DecodeString(c_b64)

   tt := curve.Fexp(curve.Ate(R,Sa))
   //fmt.Println(tt.ToString())
   H2_d := H2(tt,len(msg))
   m_d := xor([]byte(c_decoded), H2_d)

   //message décodé
   fmt.Print(string(m_d))

}