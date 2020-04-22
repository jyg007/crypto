package main

import (
	"fmt"
	util "decabe/utils"
	curve "decabe/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
	//"sync"

	//hex "encoding/hex"
)


type  MASTERKEY struct {
	PK *PUBLICKEY
	SK *SECRETKEY
}


type  PUBLICKEY struct {
	pka *curve.FP48
	pky *curve.ECP
}


type SECRETKEY struct {
	alpha  *curve.BIG
	y  *curve.BIG

}


// 
func (M *MASTERKEY) Init() {
	rnd := util.GetRand()
	M.SK = new(SECRETKEY)
	M.PK = new(PUBLICKEY)
	M.SK.alpha = util.RandModOrder(rnd)
	M.SK.y = util.RandModOrder(rnd)

	M.PK.pka = util.GenGT.Pow(M.SK.alpha)
	M.PK.pky = util.GenG1.Mul(M.SK.y)	
}



func H1( a []byte ) (*curve.BIG) {	
	h := make([]byte,curve.MODBYTES)

	hash:=sha3.NewShake256()
	hash.Write(a)
	hash.Read(h)
	d := curve.FromBytes(h)
	d.Mod(util.GroupOrder)
	return d
}





func main() {


	// Authority Setup
	n := 4

	Org_MASTER := make ([]*MASTERKEY,n)

	for i:=0;i<n;i++ {
		Org_MASTER[i] = new(MASTERKEY)
		Org_MASTER[i].Init()
	}
	

	A := [4][1]int{{1},{1},{1},{1}}
	p := [4]int{0,1,2,3}

//	fmt.Println(A[3][0])
// fmt.Println(p[0])


}
