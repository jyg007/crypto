package main

import (
	"fmt"
	"os"
	"strconv"
	//"crypto/rand"
	//amcl "github.com/miracl/core/go/core"
	curve "github.com/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
)

var GenG1 = curve.NewECPbigs(
	curve.NewBIGints(curve.CURVE_Gx),
	curve.NewBIGints(curve.CURVE_Gy))

// GenG2 is a generator of Group G2


var GenG2 = curve.NewECP8fp8s(
	curve.NewFP8fp4s(
		curve.NewFP4fp2s(
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pxaaa), curve.NewBIGints(curve.CURVE_Pxaab)),
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pyaaa), curve.NewBIGints(curve.CURVE_Pyaab))),
		curve.NewFP4fp2s(
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pxaba), curve.NewBIGints(curve.CURVE_Pxabb)),
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pyaba), curve.NewBIGints(curve.CURVE_Pyabb)))),
	curve.NewFP8fp4s(
		curve.NewFP4fp2s(
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pxbaa), curve.NewBIGints(curve.CURVE_Pxbab)),
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pybaa), curve.NewBIGints(curve.CURVE_Pybab))),
		curve.NewFP4fp2s(
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pxbba), curve.NewBIGints(curve.CURVE_Pxbbb)),
			curve.NewFP2bigs(curve.NewBIGints(curve.CURVE_Pybba), curve.NewBIGints(curve.CURVE_Pybbb)))))

// GenGT is a generator of Group GT
var GenGT = curve.Fexp(curve.Ate(GenG2, GenG1))


// GroupOrder is the order of the groups
var GroupOrder = curve.NewBIGints(curve.CURVE_Order)

// FieldBytes is the bytelength of the group order
var FieldBytes = int(curve.MODBYTES)

func hashToECP(msg []byte) (*curve.ECP) {
	c := 0
	var cont bool = true

	// à aligner en fonction de MODBIT soit 73*8 qui designe le format max des BIG
	// la fonction SHA doit etre aligner en fonction de la courbe et de la variable MODBIT (ici 73*8 => 584 , SHA584)
	hBIG := make([]byte,73)

	a := curve.NewBIG()
	h := curve.NewECP()

	for cont {
		hash:=sha3.NewShake256()
		hash.Write([]byte(strconv.Itoa(c)))
		hash.Write([]byte("***END***"))
		hash.Write([]byte(msg))
		hash.Read(hBIG)
		a = curve.FromBytes(hBIG[:])
		h=curve.NewECPbig(a)
		if h.Is_infinity() {
			c++
			// fmt.Println("Blurp")
		} else {
			cont = false
		}
	}
	return h
}


func main() {
	msg := os.Args[1]
	fmt.Println(msg)

	h := hashToECP([]byte(msg))

	fmt.Print("Point de ECP correspondant: ",h.ToString())
          
}