package main

import (
	"fmt"
	util "chameleon/utils"
	curve "chameleon/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"

	//hex "encoding/hex"
)


//Lin an Al. triple trapdoor (extend double trapdoor function)
func ECDLChameleonHash(K *curve.ECP  , Y *curve.ECP,  m []byte, r *curve.BIG) (*curve.ECP) {
	ftk := f_tk(H1(m),K)

	res := K.Mul2(ftk,Y,r)
	return res

}

func f_tk (a *curve.BIG,b *curve.ECP ) (*curve.BIG){
	nn := make([]byte,int(8*(curve.MODBYTES)))    

	n := make([]byte,int(8*(curve.MODBYTES))) 
	a.ToBytes(n)

	hash:=sha3.NewShake256()
	hash.Write(n)
	hash.Write(util.EcpToBytes(b))
	hash.Read(nn)

	d := curve.FromBytes(nn)
	d.Mod(util.GroupOrder)

	return d
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


func getCollision(K *curve.ECP, x *curve.BIG , k *curve.BIG, mPrime []byte, m []byte, r *curve.BIG) (*curve.BIG) {
	f1 := f_tk(H1(m),K)
	f2 := f_tk(H1(mPrime),K)
	f := util.Modsub(f1,f2,util.GroupOrder)
	invx := curve.NewBIGcopy(x)
	invx.Invmodp(util.GroupOrder)
	rPrime := curve.Modmul(k,invx,util.GroupOrder)
	rPrime = curve.Modmul(rPrime,f,util.GroupOrder)
	return curve.Modadd(rPrime,r,util.GroupOrder)
}

func main() {

	rnd := util.GetRand()
	//Recipient Trapdoor private key
	k := util.RandModOrder(rnd)
	x := util.RandModOrder(rnd)
	//tk := util.RandModOrder(rnd)

	//Recipient public hash keys
	K := util.GenG1.Mul(k)
	Y := util.GenG1.Mul(x)



	r := util.RandModOrder(rnd)
	m := []byte("Hello salut la compagnie")

	fmt.Println("Hash(",string(m),",",r.ToString())
	fmt.Println(ECDLChameleonHash(K,Y,m,r).ToString())

	mPrime := []byte("blablabla je vais tout masquer")

	//Hm := util.H1(m)
	rPrime := getCollision(K,x,k,mPrime,m,r)


	fmt.Println()
	fmt.Println("Hash(",string(mPrime),",",rPrime.ToString())
	fmt.Println(ECDLChameleonHash(K,Y,mPrime,rPrime).ToString())

}