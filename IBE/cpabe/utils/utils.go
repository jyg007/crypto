package utils

import (
	"fmt"
	"crypto/rand"
	amcl "cpabe/miracl/core/go/core"
	curve "cpabe/miracl/core/go/core/BLS48581"
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

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
func Modsub(a, b, m *curve.BIG) *curve.BIG {
        return curve.Modadd(a, curve.Modneg(b, m), m)
}

func EcpToBytes(E *curve.ECP) []byte {
	length := 2*FieldBytes + 1
	res := make([]byte, length)
	E.ToBytes(res, false)
	return res
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

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************

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