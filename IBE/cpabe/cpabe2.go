package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	 hex "encoding/hex"
//	"os"
//	"strconv"
	"crypto/rand"
	amcl "github.com/miracl/core/go/core"
	curve "github.com/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
)

type Cipher struct {
	C *curve.ECP
	Cprime *curve.FP48
	Cj []*curve.ECP8
	Cjprime []*curve.ECP
}

type SecretKey struct {
	D *curve.ECP8
	Dj []*curve.ECP
	Djprime []*curve.ECP8
	user_attr []string

}

type PublicKey struct {
	h *curve.ECP
    ealpha *curve.FP48 
}


const OR=1
const AND=2


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

type NODE struct {
    parent int  // index of the parent node
    leaves []int
    threshold  int     	//threshold 1 pour OR et nombre de leafs si AND
    attr int     // index de l attribut teste ici
    x []*curve.BIG   // represente les points du polynome au noeud en fonction du threshold
    y []*curve.BIG
}

func (n *NODE) SetChildren(children []int , threshold int) {
	rnd := GetRand()
	 n.leaves = children
	 n.threshold = threshold
	for i := len(n.x) ; i<threshold;i++ {
	   	n.x = append(n.x,curve.NewBIGint(10+i))
	   	n.y = append(n.y,RandModOrder(rnd))
	}
}

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
func (n *NODE) Lagrange_Interpolate(x *curve.BIG) (*curve.BIG) {
	est := curve.NewBIGint(0)
	for i := 0; i < len(n.x); i++ {
		prod := curve.NewBIGcopy(n.y[i])

		for j := 0; j < len(n.x); j++ {
			if i != j {
		
				tmp1 := Modsub(x,n.x[j],GroupOrder)  
				tmp2 := Modsub(n.x[i],n.x[j],GroupOrder)
				tmp2.Invmodp(GroupOrder)
				prod = curve.Modmul(prod,tmp1,GroupOrder)
				prod = curve.Modmul(prod,tmp2,GroupOrder)
			}
		}
		est = curve.Modadd(prod,est,GroupOrder)
	}
	return est
}

//********************************************************************************************************************************************************************
//******************************************************************************************************************************************************************** 
// utilisé pour le decryption - ne connait pas la valeur de y
func Lagrange_Interpolate2(n []*curve.BIG, i int) (*curve.BIG) {
	
	x := curve.NewBIGint(0)

	prod := curve.NewBIGint(1)
	tmp1 := curve.NewBIG()
	tmp2 := curve.NewBIG()
	
	for j := 0; j < len(n); j++ {
		if i != j {
			tmp1 = Modsub(x,n[j],GroupOrder)  
			tmp2 = Modsub(n[i],n[j],GroupOrder)
			tmp2.Invmodp(GroupOrder)
			prod = curve.Modmul(prod,tmp1,GroupOrder)
			prod = curve.Modmul(prod,tmp2,GroupOrder)
		}
	}
		
	return prod
}


type Policy struct {
	s *curve.BIG
	rnd *amcl.RAND
	tree_nodes [] *NODE
	leaves_nodes []int
	nodes_nb int
	attr_proof []string
}


    // Modelisation polynomiqle (voir lecture 14) de condition a ou b (simple...)
    // on part ici dans un test a1 OR a2 
    //  Le polynome est donc de degre 0 (condition Or sur les racine de polynome) .  soit de la forme qR(x) = i  , on a dont qR(0) = s qui force i = s
    //  on a deux conditions pour test a1 et q2  q1(0)=qR(r1) soit forcement s et de meme q2(0)=qR(r2) soit forcement s egamenet
    //   donc q1(x)=q2(x)=qR(x)=s  

func (p *Policy) Init() {
	   	p.rnd = GetRand()
	   	p.s = RandModOrder(p.rnd)   // je pense propre à la policy	

	   	//construction du noeud racine
	   	p.tree_nodes = make([]*NODE,1)
	   	p.tree_nodes[0] = new (NODE)
	   	p.tree_nodes[0].x = make([]*curve.BIG,1)
	    p.tree_nodes[0].y = make([]*curve.BIG,1)
	    p.tree_nodes[0].x[0] = curve.NewBIGint(0)
	    p.tree_nodes[0].y[0] = p.s
}

func (p *Policy) AddLeave(parent int, attr int) {
	   	n := new (NODE)
	   	n.parent = parent
	   	n.attr =attr
   	
	   	n.x = make([]*curve.BIG,1)
	    n.y = make([]*curve.BIG,1)
	 //	n.threshold = 1
	   	p.tree_nodes = append(p.tree_nodes,n)
	   	p.leaves_nodes = append(p.leaves_nodes,len(p.tree_nodes)-1)
}

func (p *Policy) SetAttributes( attributes_array []string) {
	p.attr_proof = attributes_array
}

// l arbre, qR(0) , k le noeud et x la valeur demander par exemple qk(x)
func (p *Policy) getq0(k int, x int)  ( *curve.BIG) {
//	fmt.Println("--q",k,"(",x,")")
	if (x ==0) {
		if ( k ==0 ) {
			// en fait jamais appelé ?
			fmt.Println("k =>" ,p.tree_nodes[k].threshold)
			return p.s	
		}
		p.tree_nodes[k].x[0] = curve.NewBIGint(0)
		p.tree_nodes[k].y[0] = p.getq0(p.tree_nodes[k].parent,k)
		return p.tree_nodes[k].y[0]
	}
//	fmt.Println("Lagrange ",k,"",x)
	X := curve.NewBIGint(x)
	return p.tree_nodes[k].Lagrange_Interpolate(X)
}

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
func (p *Policy )Decrypt2( SK *SecretKey , CipherData *Cipher, x int)  (*curve.FP48) {
	offset_leaves := 1  //(indique le noeud ou commence la premiere leave)
	fmt.Println("Calcul de F_",x);
	if len(p.tree_nodes[x].leaves)==0 {

		//calcul Lagrangien
		i := p.tree_nodes[x].attr   // attribut du noeud

		if (SK.user_attr[i]=="") {
			return curve.NewFP48int(0)
		}

	//	fmt.Println("***",x-offset_leaves,i)   //  decalage entre tableau noeuds totaux et tableau des leaves
		eCD := curve.Fexp(curve.Ate(CipherData.Cj[x-offset_leaves],SK.Dj[i]))
   		eCD_prime := curve.Fexp(curve.Ate(SK.Djprime[i],CipherData.Cjprime[x-offset_leaves]))
   		eCD_prime.Inverse()
   		eCD.Mul(eCD_prime)

		return eCD
	}


	FFx := make([]*curve.FP48,0)   //calcul de F(z)  où z est un nœud des feuilles que nous parcourons
	FFx2 := make([]*curve.BIG,0)   // index(z) 

    // parcourons les leaves de ce noeud pour le calculer
	for i:=0 ; i< len(p.tree_nodes[x].leaves);i++ { 
		leave_node := p.tree_nodes[ p.tree_nodes[x].leaves[i] ]
		if (p.attr_proof[leave_node.attr] == "" ) {
			fmt.Println("Param non defini pour l utilisateur:", p.attr_proof[leave_node.attr])
		} else {
			    tmp := p.Decrypt2(SK, CipherData, p.tree_nodes[x].leaves[i])
			    if (!tmp.Equals(curve.NewFP48int(0))) {
			    	   fmt.Println("ok")
			    		FFx = append(FFx,tmp)
						FFx2 = append(FFx2,curve.NewBIGint(p.tree_nodes[x].leaves[i]))
			    }
		}
	}

   	Fx := curve.NewFP48int(1)
   	for i:=0;i<len(FFx);i++ { 
	    Fx.Mul(FFx[i].Pow(Lagrange_Interpolate2(FFx2,i)))
   	}
	return Fx
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
	

type MASTERKEY struct {
	alpha *curve.BIG
	beta *curve.BIG

	pk *PublicKey 

}

func ( m*MASTERKEY) Init() {
	rnd := GetRand()
    m.alpha = RandModOrder(rnd)
	m.beta = RandModOrder(rnd)
	m.pk = new (PublicKey)
    m.pk.h = GenG1.Mul(m.beta)
    m.pk.ealpha = GenGT.Pow(m.alpha)
}


func ( p *Policy) GenKEYPAIR(MASTER *MASTERKEY, a []string) (*SecretKey,*PublicKey) {
	var i int
	SK := new(SecretKey)
	SK.user_attr = make([]string,len(a))
	copy(SK.user_attr,a)

  // s := RandModOrder(rnd)   // je pense propre à la policy
   
   SK.Dj = make([]*curve.ECP,len(p.attr_proof))
   SK.Djprime = make([]*curve.ECP8,len(p.attr_proof))
 
   // (r, r1,r2) defini par utilisateur
   r := RandModOrder(p.rnd)

   r_attr := make([]*curve.BIG,len(p.attr_proof))
   for i = 0 ; i < len(p.attr_proof) ; i++ {
   	  r_attr[i] = RandModOrder(p.rnd)
   }

   tmp1 := curve.Modadd(MASTER.alpha,r, GroupOrder )
   betainv := curve.NewBIGcopy(MASTER.beta)
   betainv.Invmodp(GroupOrder)
   puis := curve.Modmul(tmp1,betainv,GroupOrder)
   SK.D = GenG2.Mul(puis)

   // q1(0) = s et q2(0) = s ici, sinon voir doc et poly de Lagrange pour interpolation
 
   // creation de D pour tous les attributs

    for i = 0 ; i < len(p.attr_proof) ; i++ {
 	  tmp6 := curve.ECP_mapit([]byte(a[i])).Mul(r_attr[i])
   	  tmp7 := GenG1.Mul(r)
      tmp7.Add(tmp6)
      SK.Dj[i] = curve.NewECP()
      SK.Dj[i].Copy(tmp7)
      SK.Djprime[i] = GenG2.Mul(r_attr[i])
   }
   return SK,MASTER.pk

}

func ( p *Policy) Encrypt(PK *PublicKey, m *curve.FP48) (*Cipher) {
   
   CipherData := new(Cipher)

   CipherData.Cprime = m

   //on encode
   CipherData.Cprime.Mul(PK.ealpha.Pow(p.s))

   CipherData.C = PK.h.Mul(p.s)  // Gen 1

   // voir plus haut les fonctions q sont constants et toujours égales à s (clé de la policy)
   
  // CipherData.Cj = make([]*curve.ECP8,leaves_nb)
   //CipherData.Cjprime = make([]*curve.ECP,leaves_nb)
   CipherData.Cj = make([]*curve.ECP8,len(p.leaves_nodes))
   CipherData.Cjprime = make([]*curve.ECP,len(p.leaves_nodes))


   // ici on parcourt les feuilles et non les listes d attributs.  Exemple un attribut peut revenir deux fois.
   for i := 0 ; i < len(p.leaves_nodes) ; i++ {
   	  // y := leaves_nodes[i]
   	  // q0 := getq_zero(&policy,s,y,0)
   	   y := p.leaves_nodes[i]
   	   q0:=p.getq0(y,0)
       CipherData.Cjprime[i] = curve.ECP_mapit([]byte( p.attr_proof[ p.tree_nodes[y].attr] )).Mul(q0)
       CipherData.Cj[i] = GenG2.Mul(q0)

   }
   return CipherData

} 


func (p *Policy) Decrypt(SK *SecretKey, CipherData *Cipher) (*curve.FP48) {

   eCD := p.Decrypt2(SK,CipherData,0)

   // on n utilise que le premier indice.

   A := curve.NewFP48copy(eCD)
   A.Inverse()

   T1 := curve.Fexp(curve.Ate(SK.D,CipherData.C))
   T1.Mul(A)
 

   T1.Inverse()

   m := curve.NewFP48copy(CipherData.Cprime)

   m.Mul(T1)
   return m
}


//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************

func main() {

	POLICY := new(Policy)
	POLICY.Init()
	POLICY.AddLeave(0,0)   //noeud parent (ici 0, le root) et attribut (0 index dans attr_proof)
	POLICY.AddLeave(0,1)
	POLICY.AddLeave(0,2)
	POLICY.tree_nodes[0].SetChildren( []int{1 , 2,3} , 2 )    // tableau des children et le threeshold 2 pour deux leaves valides, 3 pour 3 leaves valides

	POLICY.SetAttributes([]string{"companyA","companyB","auditor"})
  
  

	//tableau à deux attribut que l on definit avec une valeur plutot qu un bit
	// a represente les attributes de celui qui veut accesder à la preuve
	a :=make([]string,len(POLICY.attr_proof))

     a[0]= "companyA"
    //a[0] = ""
    a[1] = "companyB"

    a[2] = "auditor"
    //MASTER
	//initialization de la master key pour la central authority

	MASTER := new (MASTERKEY)
	MASTER.Init()
   
    // pk => G1, h ealpha 
// generer la pubkey pour encrypt


   // ******************************************************
   //KEYGEN
   // ******************************************************

   SK, PK := POLICY.GenKEYPAIR(MASTER,a)
   // Le user prend D, Dj et Djprime en tant que private key


   // ******************************************************
   // ENCRYPT   with pk (ealpha, h)
   // ******************************************************
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)

   m := RandFP(POLICY.rnd)
   fmt.Println("Key pour l encodage: ",hex.EncodeToString(Hash_AES_Key(m)))

   CipherData := POLICY.Encrypt(PK,m)

   // ******************************************************
   // DECRYPT
   // ******************************************************
   
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)
   m1 := POLICY.Decrypt(SK,CipherData)  

   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m1)))
 
}
