package main

import (
	"fmt"
	util "decabe/utils"
	curve "decabe/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
	//"sync"

	hex "encoding/hex"
)


type  MASTERKEY struct {
	PK *PUBLICKEY
	SK *SECRETKEY
}


type  PUBLICKEY struct {
	pka *curve.FP48
	pky *curve.ECP8
}

type SECRETKEY struct {
	alpha  *curve.BIG
	y  *curve.BIG
}

type USERKEY struct {
	K *curve.ECP
	attribute_index int
}

type CIPHER struct {
	C0 *curve.FP48
	C1 *curve.FP48
	C2 *curve.ECP8
	C3 *curve.ECP8
}



// 
func NewMASTERKEY() *MASTERKEY{
	rnd := util.GetRand()
	M := new(MASTERKEY)
	M.SK = new(SECRETKEY)
	M.PK = new(PUBLICKEY)
	M.SK.alpha = util.RandModOrder(rnd)
	M.SK.y = util.RandModOrder(rnd)

	M.PK.pka = curve.NewFP48copy(util.GenGT)
	M.PK.pka = M.PK.pka.Pow(M.SK.alpha)
	M.PK.pky = curve.NewECP8()
	M.PK.pky = util.GenG2.Mul(M.SK.y)	
	return M
}

func NewUSERKEY(a *curve.ECP, i int) *USERKEY {
	K := new(USERKEY)
	K.K = a
	K.attribute_index = i
	return K
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


func MatrixMul( A [][]int,   v[] *curve.BIG ,x int) (*curve.BIG) {

	col_nb := len(A[0][:])
	//line_nb := len(A[:])
	fmt.Println(A[x][:])
	
	//fmt.Println(len(A[][]))
	tot := curve.NewBIGint(0)
	for i:=0 ; i<col_nb;i++ {
		tmp := curve.NewBIGint(A[x][i])
		tmp = curve.Modmul(tmp,v[i],util.GroupOrder)
		tot = curve.Modadd(tmp, tot,util.GroupOrder)
	}
	return tot
}


func Encrypt(M *curve.FP48, A [][]int, p []int, ATTRIBUTE_MASTER[]*MASTERKEY) []CIPHER {
	n := len(A)


	l := len(A[0])


	rnd := util.GetRand()
	s := util.RandModOrder(rnd)

	v := make([]*curve.BIG,l)
	v[0] = new(curve.BIG)
	v[0] = curve.NewBIGcopy(s)
	if l > 0 {
		for i:=1;i<l;i++ {
			v[i] = new(curve.BIG)
			v[i] = util.RandModOrder(rnd)
		}
	}

	w := make([]*curve.BIG,l)
	w[0] = new(curve.BIG)
	w[0] = curve.NewBIGint(0)
	if l > 0 {
		for i:=1;i<l;i++ {
			w[i] = new(curve.BIG)
			w[i] = util.RandModOrder(rnd)
		}
	}



	CipheredData := make([]CIPHER,n)
	r := curve.NewBIG()

	C0 := util.GenGT.Pow(s)
	C0.Mul(M)

	for i:=0;i<n;i++ {
		CipheredData[i].C0 = C0

		r = util.RandModOrder(rnd)

		CipheredData[i].C1 = ATTRIBUTE_MASTER[p[i]].PK.pka.Pow(r)

		lx := MatrixMul(A,v,i)
		CipheredData[i].C1.Mul(util.GenGT.Pow(lx))

		CipheredData[i].C2 = util.GenG2.Mul(r)

		wx := MatrixMul(A,w,i)

		CipheredData[i].C3 = ATTRIBUTE_MASTER[p[i]].PK.pky.Mul(r) 
		CipheredData[i].C3.Add(util.GenG2.Mul(wx))
	
	}
	return CipheredData

}


func KEYGEN(GID []byte,  SK *SECRETKEY, attr int) (*USERKEY) {
	K := NewUSERKEY(util.GenG1.Mul2(SK.alpha,curve.ECP_mapit([]byte(GID)),SK.y),attr)
	return K
}


func DECRYPT( CipheredData []CIPHER, K []*USERKEY, GID string, p []int,c []int) *curve.FP48 {
	n := len(K)

	D := make([]*curve.FP48,n)
    for Ki,Kval := range K {
        // fait la correspondance entre la clé fourni et la partie encrypté auquelle elle se rapporte
        // on cherche la ligne de la matrice à laquelle correspond la clé
        // i correspond à un numéro de ligne de la matrice A
    	// p(i) pointe sur l attribut correspondant
    	// donc Kval.attribute_index = p[i], et i=p-1(Kval.attribute_index)
        var i int
    	for k, v := range p {
    		//k ligne de la matrice K, p[k]  attribut correspondant
    		if v == Kval.attribute_index {
    			i=k
    			break
    		}
    	}

	    D[Ki] = curve.NewFP48copy(CipheredData[i].C1)
	    t1 := curve.Fexp(curve.Ate(CipheredData[i].C3,curve.ECP_mapit([]byte(GID))))
	    D[Ki].Mul(t1)
	  
	    t2 := curve.Fexp(curve.Ate(CipheredData[i].C2,Kval.K))  //p[i] doit corrponds à un attribute_index, i étant un numéro de ligne de A

	    t2.Inverse()
	    D[Ki].Mul(t2)
	    if (c[i] > 0) {
	        D[Ki] = D[Ki].Pow(curve.NewBIGint(c[i]))
	    } else if c[i] < 0 {
			kk := curve.NewBIGint(-c[i])
			kk = curve.Modneg(kk,util.GroupOrder)	
		  D[Ki] = D[Ki].Pow(kk)
	    } else {
	    	D[Ki] = curve.NewFP48int(1)
	    }


	  //  D[i] = D[i].Pow(curve.NewBIGint(c[i]))

	}

	tot := curve.NewFP48int(1)
	for i:=0;i<n;i++ {
	    tot.Mul(D[i])
	}
	U := curve.NewFP48copy(CipheredData[0].C0)
	tot.Inverse()
	U.Mul(tot)
	return U
}

func main() {

	rnd := util.GetRand()

	// Cas de 4 sociétés gérant chacun un attribut.
	// Les deux premieres sociétés peuvent lire la donnée mais pas la troisième.
	// on fait le test avec quatre employés, ceux autorisés et les autres
	A := [][]int{{1},{1},{1},{1}}
	p := []int{0,1,2,3}
	n := len(A)
	c := []int{1,-1,1,0}  //(tels que Sum cxAx = 0)
	// Authority Setup/	n := 4


	ATTRIBUTE_MASTER := make ([]*MASTERKEY,n)

	for i:=0;i<len(ATTRIBUTE_MASTER);i++ {
		ATTRIBUTE_MASTER[i] = NewMASTERKEY()
	}

	// on va faire ligne par ligne

	//A := [][]int{{1},{1},{1}}


	// maps row of the matrices to the attributes


    M := util.RandFP(rnd)
    fmt.Println("Key pour l encodage: ",hex.EncodeToString(util.Hash_AES_Key(M)))

	CipheredData := Encrypt(M,A,p,ATTRIBUTE_MASTER)

	//	MatrixMul(A,p,v,1)
	GID := "jeanyves.girard@ibm.com"

	//Keygen for a user gid and an attribute i
    var K []*USERKEY
   /* for i:=0;i<n;i++ {
	  	K[i] = KEYGEN([]byte(GID),ATTRIBUTE_MASTER[i].SK,i)
	}*/
	// l organisation qui gere l attribyt 2 signe
	K = append(K, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[2].SK,2) )

	// Decrypt

	U := DECRYPT(CipheredData, K,GID,p,c)

	fmt.Println("Key pour le decodage AES: ",hex.EncodeToString(util.Hash_AES_Key(U)))

}


