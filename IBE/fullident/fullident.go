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


func H1( a []byte ,b []byte  ) (*curve.BIG) {	
	h := make([]byte,curve.MODBYTES)

	hash:=sha3.NewShake256()
	hash.Write(a)
	hash.Write(b)
	hash.Read(h)
	return curve.FromBytes(h)
}



func G1( a []byte , nh int ) ([]byte) {	
	h := make([]byte,nh)

	hash:=sha3.NewShake256()
	hash.Write(a)
	hash.Read(h)
	return h
}




func main() {
   msg := "Bonjour comment allez vous, ceci est merveilleux"

	//initialization de la master key pour la central authority
   rnd := GetRand()
   s := RandModOrder(rnd)
   Ppub := GenG2.Mul(s)

   //encryption
   //key generation, envoi d un fichier à jeanyves.girard@fr.ibm.com
   id := "jeanyves.girard@fr.ibm.com"
   Qid:=curve.ECP_mapit([]byte(id))

   //generation de n charactere aléatoire
   sigma :=  make([]byte, len(msg))
    _, _ = rand.Read(sigma)
   // fmt.Println("sigma: ",b64.StdEncoding.EncodeToString(sigma))

    r := curve.NewBIG()
    r = H1(sigma,[]byte(msg))

    CU := GenG2.Mul(r)

    Gid := curve.Fexp(curve.Ate(Ppub,Qid))
    CV := xor(sigma,H2(Gid.Pow(r),len(msg)))

    CW := xor([]byte(msg),G1(sigma,len(msg))) 

    fmt.Println(CU.ToString())
	fmt.Println(b64.StdEncoding.EncodeToString(CV))
	fmt.Println(b64.StdEncoding.EncodeToString(CW))


    // passage des paramètres sur réseau
	nn := make([]byte,int(3*2*2*2*(curve.MODBYTES)))     // 3 FP8 soit 3x2 FP4 soit 3x2x2 FP2 soit 3x2x2x2 FP
	CU.ToBytes(nn,false)
	CU_b64 := b64.StdEncoding.EncodeToString(nn)
	CV_b64 := b64.StdEncoding.EncodeToString(CV)
	CW_b64 := b64.StdEncoding.EncodeToString(CW)

	//decryption en utilisation C <U,V,W>


	//decryption des parametres recus en base64
	tmp,_ := b64.StdEncoding.DecodeString(CU_b64)
	CU_dec := curve.ECP8_fromBytes(tmp)
	CV_dec, _ := b64.StdEncoding.DecodeString(CV_b64)
	CW_dec, _ := b64.StdEncoding.DecodeString(CW_b64)

    did := Qid.Mul(s)   // cle prive du receveur jeanyevs.girard@fr.ibm.com

    sigma_dec := xor(CV_dec,H2(curve.Fexp(curve.Ate(CU_dec,did)),len(CV_dec)))
    //fmt.Println(b64.StdEncoding.EncodeToString(sigma_dec))

    M_dec := xor(CW_dec,G1(sigma_dec,len(sigma_dec)))  // msg decodé
    
    fmt.Println()
	fmt.Println()
    
    fmt.Println("Message decodé:",string(M_dec))

    r_dec := H1(sigma_dec,M_dec)
    Udec := GenG2.Mul(r_dec)
    if CU.Equals(Udec) {
    	fmt.Println("Parfait, U=rP")
    } else {
    	fmt.Println("il y a un soucis")
    }

}