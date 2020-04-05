package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	 hex "encoding/hex"
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

// FieldBytes is the bytelength of the group order
var FieldBytes = int(curve.MODBYTES)
// GroupOrder is the order of the groups
var GroupOrder = curve.NewBIGints(curve.CURVE_Order)

func EcpToBytes(E *curve.ECP) []byte {
	length := 2*FieldBytes + 1
	res := make([]byte, length)
	E.ToBytes(res, false)
	return res
}


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


func RandFP(rng *amcl.RAND) *curve.FP48 {

	// curve order q
	q := curve.NewBIGints(curve.CURVE_Order)


	fp := make([]*curve.FP,48)
	fp2 := make([]*curve.FP2,24)
	fp4 := make([]*curve.FP4,12)
	fp8 := make([]*curve.FP8,6)
	fp16 := make([]*curve.FP16,3)

	var i int
	// Take random element in Zq
	for i=0;i<48;i++ {
		fp[i] = curve.NewFPbig(curve.Randomnum(q, rng))
	} 
	for i=0;i<24;i++ {
		fp2[i] = curve.NewFP2fps(fp[2*i],fp[2*i+1])
	} 
	for i=0;i<12;i++ {
		fp4[i] = curve.NewFP4fp2s(fp2[2*i],fp2[2*i+1])
	} 
	for i=0;i<6;i++ {
		fp8[i] = curve.NewFP8fp4s(fp4[2*i],fp4[2*i+1])
	} 
	for i=0;i<3;i++ {
		fp16[i] = curve.NewFP16fp8s(fp8[2*i],fp8[2*i+1])
	} 

	return  curve.NewFP48fp16s(fp16[0],fp16[1],fp16[2])

}


// nh longueur du hash à generer qui depend ici de la longueur du message. 
// hash de Gt vers {0,1}^m

func Hash_AES_Key(n *curve.FP48 ) ([]byte) {
    // FP48 a 3 FP16 qui a 2 FP8 qui 2 FP4 qui 2 FP2 qui 2 FP
	nn := make([]byte,int(3*2*2*2*2*(curve.MODBYTES)))    
	n.ToBytes(nn)

	h := make([]byte,32)

	hash:=sha3.NewShake256()
	hash.Write(nn)
	hash.Read(h)
	return h
}





func main() {

    a1 := "ibm=y"
    a2 := "airbus=y"

    //nombre d attribut
	n:=2 

    //MASTER
	//initialization de la master key pour la central authority
   	rnd := GetRand()
    alpha := RandModOrder(rnd)
	beta := RandModOrder(rnd)
    h := GenG1.Mul(beta)
    ealpha := GenGT.Pow(alpha)
   

    // pk => G1, h ealpha 


    // Modelisation polynomiqle (voir lecture 14) de condition a ou b (simple...)
    // on part ici dans un test a1 OR a2 
    //  Le polynome est donc de degre 0 (condition Or sur les racine de polynome) .  soit de la forme qR(x) = i  , on a dont qR(0) = s qui force i = s
    //  on a deux conditions pour test a1 et q2  q1(0)=qR(r1) soit forcement s et de meme q2(0)=qR(r2) soit forcement s egamenet
    //   donc q1(x)=q2(x)=qR(x)=s  

 


   // ******************************************************
   //KEYGEN
   // ******************************************************
   
   s := RandModOrder(rnd)   // je pense propre à la policy
   
   Dj := make([]*curve.ECP,n)
   Djprime := make([]*curve.ECP8,n)
 
   // (r, r1,r2) defini par utilisateur
   r := RandModOrder(rnd)
   r1 := RandModOrder(rnd)
   r2 := RandModOrder(rnd)


   tmp1 := curve.Modadd(alpha,r, GroupOrder )
   betainv := curve.NewBIGcopy(beta)
   betainv.Invmodp(GroupOrder)
   puis := curve.Modmul(tmp1,betainv,GroupOrder)
   D := GenG2.Mul(puis)

   // q1(0) = s et q2(0) = s ici, sinon voir doc et poly de Lagrange pour interpolation
 
   tmp6 := curve.ECP_mapit([]byte(a1)).Mul(r1)
   tmp7 := GenG1.Mul(r)
   tmp7.Add(tmp6)
   Dj[0] = curve.NewECP()
   Dj[0].Copy(tmp7)
 
   tmp6 = curve.ECP_mapit([]byte(a2)).Mul(r2)
   tmp7 = GenG1.Mul(r)
   tmp7.Add(tmp6)
   Dj[1] = curve.NewECP()
   Dj[1].Copy(tmp7)
 

   Djprime[0] = GenG2.Mul(r1)
   Djprime[1] = GenG2.Mul(r2)

  // Le user prend D, Dj et Djprime en tant que private key

   // ******************************************************
   // ENCRYPT   with pk (ealpha, h)
   // ******************************************************
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)

   Cprime := RandFP(rnd)
   fmt.Println("Key pour l encodage: ",hex.EncodeToString(Hash_AES_Key(Cprime)))

   //on encode
   Cprime.Mul(ealpha.Pow(s))

   C := h.Mul(s)  // Gen 1

   // voir plus haut les fonctions q sont constants et toujours égales à s (clé de la policy)
   
   Cj := make([]*curve.ECP8,n)
   Cjprime := make([]*curve.ECP,n)

   Cjprime[0] = curve.ECP_mapit([]byte("ibm=y")).Mul(s)
   Cjprime[1] = curve.ECP_mapit([]byte("airbus=y")).Mul(s)

   Cj[0] = GenG2.Mul(s)
   Cj[1] = GenG2.Mul(s)



   // ******************************************************
   // DECRYPT
   // ******************************************************
   
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)

   eCD1 := curve.Fexp(curve.Ate(Cj[0],Dj[0]))
   eCD1_prime := curve.Fexp(curve.Ate(Djprime[0],Cjprime[0]))
   eCD1_prime.Inverse()
   eCD1.Mul(eCD1_prime)


   eCD2 := curve.Fexp(curve.Ate(Cj[1],Dj[1]))
   eCD2_prime := curve.Fexp(curve.Ate(Djprime[1],Cjprime[1]))
   eCD2_prime.Inverse()
   eCD2.Mul(eCD2_prime)

   A := curve.NewFP48copy(eCD1)
   A.Inverse()

   T1 := curve.Fexp(curve.Ate(D,C))
   T1.Mul(A)
 //  fmt.Println("\naa =========",T1.ToString())

   T1.Inverse()

   Cprime.Mul(T1)


   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(Cprime)))


 

}
