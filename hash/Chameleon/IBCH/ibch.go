package main

import (
	"fmt"
	util "chameleon/utils"
	curve "chameleon/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"

	//hex "encoding/hex"
)


type  MASTERKEY struct {
	a []*curve.BIG
}


type  PUBLICKEY struct {
	ID []byte
	pk []*curve.ECP8
}

func (pk *PUBLICKEY) Init(t int ) {
	pk.pk = make([]*curve.ECP8,t)
}


// trapdoor key
type SECRETKEY struct {
	ID []byte
	sk *curve.BIG
}


// 
func (M *MASTERKEY) Init( threshold int) {
	rnd := util.GetRand()
	M.a = make([]*curve.BIG,threshold)
	for i:=0;i<threshold;i++ {
		M.a[i] = util.RandModOrder(rnd)
	}
}

func (M *MASTERKEY) GenKeyPair(ID []byte) (*SECRETKEY,*PUBLICKEY) {
	PK := new(PUBLICKEY)
	SK := new(SECRETKEY)

	PK.Init(len(M.a))

	PK.ID=append(PK.ID,ID...)
	SK.ID=append(SK.ID,ID...)

	for i:=0;i<len(M.a);i++ {
		PK.pk[i] = util.GenG2.Mul(M.a[i])
	}
	SK.sk = M.f(H1(ID))

	return SK,PK
}

func (M *MASTERKEY) f(x *curve.BIG ) (*curve.BIG){

	tot := curve.NewBIGcopy(M.a[0])
	X := curve.NewBIGcopy(x)

	if len(M.a) >0 {
		for i:=1;  i<len(M.a);i++ {
			tot = curve.Modadd(tot,curve.Modmul(M.a[i],X,util.GroupOrder),util.GroupOrder)
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

func (pk *PUBLICKEY) CHash( L []byte,m []byte,R *curve.ECP) (*curve.FP48) {
	IDbar:=make([]byte,len(pk.ID)+len(L))
	copy(IDbar,pk.ID)
	IDbar=append(IDbar,L...)

	hash := curve.Fexp(curve.Ate(util.GenG2,R))
	tmpp := curve.Fexp(curve.Ate(pk.fid(H1(pk.ID)),curve.ECP_map2point(H1(IDbar)).Mul(H1(m))))
	hash.Mul(tmpp)

	return hash
}


// utilisé par le signer qui connait R et m.  Il peut générer R'', m'' sans révéler m' si en input on lui présente m' et R'
// proprité de message hiding.  Il n utilise pas la forge key pour cela !
func ForgeClaim( m []byte,R *curve.ECP, m1 []byte,R1 *curve.ECP, m2 []byte) (*curve.ECP) {

	//ephemeral trap door calculation
	Temp := curve.NewECP()
	Temp.Copy(R1)
	R1.Sub(R)
	htemp := util.Modsub(H1(m),H1(m1),util.GroupOrder)
	htemp.Invmodp(util.GroupOrder)

	EphemeralTrapdoorKey := R1.Mul(htemp)


	R2 := EphemeralTrapdoorKey.Mul(util.Modsub(H1(m),H1(m2),util.GroupOrder))
	R2.Add(R)

	return R2
}


func (sk* SECRETKEY) Forge(L []byte,mPrime []byte,m []byte, R *curve.ECP) (*curve.ECP) {
	IDbar:=make([]byte,len(sk.ID)+len(L))
	copy(IDbar,sk.ID)
	IDbar=append(IDbar,L...)

	H := curve.ECP_map2point(H1(IDbar))
	diff := util.Modsub(H1(m),H1(mPrime),util.GroupOrder)
	mul := curve.Modmul(sk.sk,diff,util.GroupOrder)
	Htemp := H.Mul(mul)

	Htemp.Add(R)
	return Htemp
}

func (PUB *PUBLICKEY) fid(x *curve.BIG ) (*curve.ECP8){
	tot := curve.NewECP8()
	tot.Copy(PUB.pk[0])
	X := curve.NewBIGcopy(x)
	//var m int
	if len(PUB.pk) >0 {
		for i:=1;  i<len(PUB.pk);i++ {
			tot.Add(PUB.pk[i].Mul(X))   // retourne un entier
			X = curve.Modmul(x,X,util.GroupOrder)
		}	
	}
	return tot
}



func main() {



	// Travail chez le receveur
	// Pour une identité, il établit une clé publique qu'il va fournir pk
	// Il garde une clé privé pour pouvoir forger un nouveau message skid

	Master := new(MASTERKEY)
	Master.Init(5)



	skid,pkid := Master.GenKeyPair([]byte("jeanyveirard@fr.ibm.com"))
	//skid2,pkid2 := Master.GenKeyPair([]byte("hu@cn.ibm.com"))

	// “Customized identity” is often used to construct key-exposure free chameleon hash. 
	// A customized identity is actually a label for each transaction. For example, we can let L = IDS ||IDR ||IDT ,
	// where IDS , IDR , and IDT denote the identity of the signer, recipient, and transaction, respectively.

	L := []byte("robert@royalcanin.fr**SecTransfer342342234")
	m := []byte("salut les copains")


	// On génére un point spécifique à envoyé
	rnd := util.GetRand()
	r := util.RandModOrder(rnd)
	R := util.GenG1.Mul(r)

	fmt.Println("Message original\n",string(m),"\n",R.ToString(),"\n\n")


	// the Signer send a message to an intented recipent that provided pubkeys
	S1:= pkid.CHash(L,m,R)
	//pkid2.CHash(L,m,R)


	// the recipient forge un nouveau messagemais a besoin de l original biensur
	mPrime := []byte("BigBisous")
	RPrime := skid.Forge(L,mPrime,m,R)

	//véficiation de la signature forgé
	S2 := pkid.CHash(L,mPrime,RPrime)
	fmt.Println("\nVérification signature tel que forgé par le recipient: ",S1.Equals(S2))
	fmt.Println(string(mPrime),"\n",RPrime.ToString(),"\n")

	//Mais non mais !

	m2 := []byte("Si je dis la vérité et je suis à l origine du message m")
	R2 := ForgeClaim(m,R,mPrime,RPrime,m2)
	S3 := pkid.CHash(L,m2,R2)

	fmt.Println("\nVérification du signer sans révéler le message en fournissant m'' et R'' comme preuve: " ,S2.Equals(S3))
	fmt.Println(string(m2),"\n",R2.ToString(),"\n")

	//Affichage de la signature
	//fmt.Println(S1.ToString())


}