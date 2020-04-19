package main

import (
	"fmt"
	util "chameleon/utils"
	curve "chameleon/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"

	//hex "encoding/hex"
)




func  f(a []*(curve.BIG) ,x *curve.BIG ) (*curve.BIG){

	tot := curve.NewBIGcopy(a[0])
	X := curve.NewBIGcopy(x)

	if len(a) >0 {
		for i:=1;  i<len(a);i++ {
			tot = curve.Modadd(tot,curve.Modmul(a[i],X,util.GroupOrder),util.GroupOrder)
			X = curve.Modmul(x,X,util.GroupOrder)
		}	
	}
	return tot
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

func CHash(pk []*(curve.ECP8), ID []byte,L []byte,m []byte,R *curve.ECP) (*curve.FP48) {
	IDbar:=make([]byte,len(ID)+len(L))
	copy(IDbar,ID)
	IDbar=append(IDbar,L...)

	hash := curve.Fexp(curve.Ate(util.GenG2,R))
	tmpp := curve.Fexp(curve.Ate(fid(pk,H1(ID)),curve.ECP_map2point(H1(IDbar)).Mul(H1(m))))
	hash.Mul(tmpp)

	return hash
}

func Forge(skid *curve.BIG, ID []byte,L []byte,mPrime []byte,m []byte, R *curve.ECP) (*curve.ECP) {
	IDbar:=make([]byte,len(ID)+len(L))
	copy(IDbar,ID)
	IDbar=append(IDbar,L...)

	H := curve.ECP_map2point(H1(IDbar))
	diff := util.Modsub(H1(m),H1(mPrime),util.GroupOrder)
	mul := curve.Modmul(skid,diff,util.GroupOrder)
	Htemp := H.Mul(mul)

	Htemp.Add(R)
	return Htemp
}

func  fid(pk []*(curve.ECP8) ,x *curve.BIG ) (*curve.ECP8){
	tot := curve.NewECP8()
	tot.Copy(pk[0])
	X := curve.NewBIGcopy(x)
	//var m int
	if len(pk) >0 {
		for i:=1;  i<len(pk);i++ {
			tot.Add(pk[i].Mul(X))   // retourne un entier
			X = curve.Modmul(x,X,util.GroupOrder)
		}	
	}
	return tot
}



func main() {
	rnd := util.GetRand()


	// Travail chez le receveur
	// Pour une identité, il établit une clé publique qu'il va fournir pk
	// Il garde une clé privé pour pouvoir forger un nouveau message skid
	t := 5
	a := make([]*curve.BIG,t)
	pk := make([]*curve.ECP8,t)

	for i:=0;i<t;i++ {
		a[i] = util.RandModOrder(rnd)
		pk[i] = util.GenG2.Mul(a[i])
	}

	ID := []byte("jeanyves.girard@fr.ibm.com")
	skid := f(a,H1(ID))

	//Master Key
//	x := util.RandModOrder(rnd)
//	sk := f(a,x)

	

//fmt.Println(util.GenG2.Mul(f(a,H1(ID))).ToString())
//fmt.Println(fid(pk,H1(ID)).ToString())

	L := []byte("robert@royalcanin.fr")
	m := []byte("salut les copains")

	mPrime := []byte("BigBisous")


	r := util.RandModOrder(rnd)
	R := util.GenG1.Mul(r)


	S1:= CHash(pk,ID,L,m,R)

	RPrime := Forge(skid,ID,L,mPrime,m,R)

	S2 := CHash(pk,ID,L,mPrime,RPrime)

	fmt.Println(S1.Equals(S2))

}