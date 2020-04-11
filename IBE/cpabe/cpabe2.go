package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	node "cpabe/node"
	 hex "encoding/hex"
	 util "cpabe/utils"
//	"crypto/rand"
	amcl "cpabe/miracl/core/go/core"
	curve "cpabe/miracl/core/go/core/BLS48581"
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
			tmp1 = util.Modsub(x,n[j],util.GroupOrder)  
			tmp2 = util.Modsub(n[i],n[j],util.GroupOrder)
			tmp2.Invmodp(util.GroupOrder)
			prod = curve.Modmul(prod,tmp1,util.GroupOrder)
			prod = curve.Modmul(prod,tmp2,util.GroupOrder)
		}
	}
		
	return prod
}


type Policy struct {
	s *curve.BIG
	rnd *amcl.RAND
	tree_nodes [] *node.NODE
	leaves_nodes []int
	nodes_nb int
	attr_proof []string
}


    // Modelisation polynomiqle (voir lecture 14) de condition a ou b (simple...)
    // on part ici dans un test a1 OR a2 
    //  Le polynome est donc de degre 0 (condition Or sur les racine de polynome) .  soit de la forme qR(x) = i  , on a dont qR(0) = s qui force i = s
    //  on a deux conditions pour test a1 et q2  q1(0)=qR(r1) soit forcement s et de meme q2(0)=qR(r2) soit forcement s egamenet
    //   donc q1(x)=q2(x)=qR(x)=s  



func (p *Policy) Init(threshold int, attributes_array []string) {
	   	p.rnd = util.GetRand()
	   	p.s = util.RandModOrder(p.rnd)   // je pense propre à la policy	
		p.attr_proof = attributes_array
	   	//construction du noeud racine
	   	p.tree_nodes = make([]*node.NODE,1)
	   	p.tree_nodes[0] = new (node.NODE)
	   	p.tree_nodes[0].X = make([]*curve.BIG,1)
	    p.tree_nodes[0].Y = make([]*curve.BIG,1)
	    p.tree_nodes[0].X[0] = curve.NewBIGint(0)
	    p.tree_nodes[0].Y[0] = p.s

	    p.tree_nodes[0].Threshold = threshold
		for i := len(p.tree_nodes[0].X) ; i<threshold;i++ {
	   		p.tree_nodes[0].X = append(p.tree_nodes[0].X,curve.NewBIGint(10+i))
	   		p.tree_nodes[0].Y = append(p.tree_nodes[0].Y,util.RandModOrder(p.rnd))
		}
}



func (p *Policy) AddLeave(parent int, attr int) (int){
	   	n := new (node.NODE)
	   	n.Parent = parent
	   	n.Attr =attr
   	

	   	n.X = make([]*curve.BIG,1)
	    n.Y = make([]*curve.BIG,1)
	 //	n.Threshold = 1
	   	p.tree_nodes = append(p.tree_nodes,n)
	    p.tree_nodes[parent].Leaves = append(p.tree_nodes[parent].Leaves,len(p.tree_nodes)-1)
	   	p.leaves_nodes = append(p.leaves_nodes,len(p.tree_nodes)-1)


	   	return len(p.tree_nodes)-1
}

func (p *Policy) AddKnot(parent int, threshold int)  (int) {
	   	n := new (node.NODE)
	   	n.Parent = parent
	      	
	   	n.X = make([]*curve.BIG,1)
	    n.Y = make([]*curve.BIG,1)

	 	n.Threshold = threshold
	   	p.tree_nodes = append(p.tree_nodes,n)
	    p.tree_nodes[parent].Leaves = append(p.tree_nodes[parent].Leaves,len(p.tree_nodes)-1)

		rnd := util.GetRand()
		//fmt.Println("Knot",len(p.tree_nodes)-1,threshold)
		for i := len(n.X) ; i<threshold;i++ {
	   		n.X = append(n.X,curve.NewBIGint(10+i))
	   		n.Y = append(n.Y,util.RandModOrder(rnd))
		}

	    n.X[0] = curve.NewBIGint(0)
	    n.Y[0] = p.getq0(parent,len(p.tree_nodes)-1)

	    return len(p.tree_nodes)-1
}



// l arbre, qR(0) , k le noeud et x la valeur demander par exemple qk(x)
func (p *Policy) getq0(k int, x int)  ( *curve.BIG) {
	//fmt.Println("--q",k,"(",x,")")
	if (x ==0) {
		if ( k ==0 ) {
			// en fait jamais appelé ?
			fmt.Println("k =>" ,p.tree_nodes[k].Threshold)
			return p.s	
		}
		p.tree_nodes[k].X[0] = curve.NewBIGint(0)
		p.tree_nodes[k].Y[0] = p.getq0(p.tree_nodes[k].Parent,k)
		return p.tree_nodes[k].Y[0]
	}
//	fmt.Println("Lagrange ",k,"",x)
	X := curve.NewBIGint(x)
	return p.tree_nodes[k].Lagrange_Interpolate(X)
}

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
func (p *Policy )Decrypt2( SK *SecretKey , CipherData *Cipher, x int)  (*curve.FP48) {
	//offset_leaves := 1  //(indique le noeud ou commence la premiere leave)
	//fmt.Println("Calcul de F_",x);
	if len(p.tree_nodes[x].Leaves)==0 {
		//calcul Lagrangien
		i := p.tree_nodes[x].Attr   // attribut du noeud

		if (SK.user_attr[i]=="") {
			return curve.NewFP48int(0)
		}

	//	fmt.Println("***",x-offset_leaves,i)   //  decalage entre tableau noeuds totaux et tableau des leaves
		eCD := curve.Fexp(curve.Ate(CipherData.Cj[x],SK.Dj[i]))
   		eCD_prime := curve.Fexp(curve.Ate(SK.Djprime[i],CipherData.Cjprime[x]))
   		eCD_prime.Inverse()
   		eCD.Mul(eCD_prime)

		return eCD
	}


	FFx := make([]*curve.FP48,0)   //calcul de F(z)  où z est un nœud des feuilles que nous parcourons
	FFx2 := make([]*curve.BIG,0)   // index(z) 

    // parcourons les leaves de ce noeud pour le calculer
    //fmt.Println("Fx",x,len(p.tree_nodes[x].leaves))
	for i:=0 ; i< len(p.tree_nodes[x].Leaves);i++ { 
		leave_node := p.tree_nodes[ p.tree_nodes[x].Leaves[i] ]
		if (p.attr_proof[leave_node.Attr] == "" ) {
			fmt.Println("Param non defini pour l utilisateur:", p.attr_proof[leave_node.Attr])
		} else {
			    tmp := p.Decrypt2(SK, CipherData, p.tree_nodes[x].Leaves[i])
			    if (!tmp.Equals(curve.NewFP48int(0))) {

			    		FFx = append(FFx,tmp)
						FFx2 = append(FFx2,curve.NewBIGint(p.tree_nodes[x].Leaves[i]))
			    } 
		}
	}

	if len(FFx) == 0 {
		return curve.NewFP48int(0)

	} else {
		Fx := curve.NewFP48int(1)
	   	for i:=0;i<len(FFx);i++ { 
		    Fx.Mul(FFx[i].Pow(Lagrange_Interpolate2(FFx2,i)))
	   	}
		return Fx	
	}

   	
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
	rnd := util.GetRand()
    m.alpha = util.RandModOrder(rnd)
	m.beta = util.RandModOrder(rnd)
	m.pk = new (PublicKey)
    m.pk.h = util.GenG1.Mul(m.beta)
    m.pk.ealpha = util.GenGT.Pow(m.alpha)
}


func ( p *Policy) GenKEYPAIR(MASTER *MASTERKEY, a []string) (*SecretKey,*PublicKey) {
	var i int
	SK := new(SecretKey)
	SK.user_attr =  a
fmt.Print(".")


  // s := util.RandModOrder(rnd)   // je pense propre à la policy
   
   SK.Dj = make([]*curve.ECP,len(p.attr_proof))
   SK.Djprime = make([]*curve.ECP8,len(p.attr_proof))
 
   // (r, r1,r2) defini par utilisateur
   r := util.RandModOrder(p.rnd)

   r_attr := make([]*curve.BIG,len(p.attr_proof))
   for i = 0 ; i < len(p.attr_proof) ; i++ {
   	  r_attr[i] = util.RandModOrder(p.rnd)
   }

   tmp1 := curve.Modadd(MASTER.alpha,r, util.GroupOrder )
   betainv := curve.NewBIGcopy(MASTER.beta)
   betainv.Invmodp(util.GroupOrder)
   puis := curve.Modmul(tmp1,betainv,util.GroupOrder)
   SK.D = util.GenG2.Mul(puis)

   // q1(0) = s et q2(0) = s ici, sinon voir doc et poly de Lagrange pour interpolation
 
   // creation de D pour tous les attributs

    for i = 0 ; i < len(p.attr_proof) ; i++ {
 	  tmp6 := curve.ECP_mapit([]byte(a[i])).Mul(r_attr[i])
   	  tmp7 := util.GenG1.Mul(r)
      tmp7.Add(tmp6)
      SK.Dj[i] = curve.NewECP()
      SK.Dj[i].Copy(tmp7)
      SK.Djprime[i] = util.GenG2.Mul(r_attr[i])
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
   CipherData.Cj = make([]*curve.ECP8,len(p.tree_nodes))
   CipherData.Cjprime = make([]*curve.ECP,len(p.tree_nodes))


   // ici on parcourt les feuilles et non les listes d attributs.  Exemple un attribut peut revenir deux fois.
   for i := 0 ; i < len(p.leaves_nodes) ; i++ {
   	  // y := leaves_nodes[i]
   	  // q0 := getq_zero(&policy,s,y,0)
   	   y := p.leaves_nodes[i]
   	   //fmt.Println(y)
   	   q0:=p.getq0(y,0)
       CipherData.Cjprime[y] = curve.ECP_mapit([]byte( p.attr_proof[ p.tree_nodes[y].Attr] )).Mul(q0)
       CipherData.Cj[y] = util.GenG2.Mul(q0)
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
	POLICY.Init(OR,[]string{"companyA","manager", "companyB", "manager","auditor"})

	//AND Valué à deux , peut être supérieur si nombre de children supérieur à 2, le prendre comme un  nOutOfm
	n1:=POLICY.AddKnot(0,AND)
	n2:=POLICY.AddKnot(0,AND)
	POLICY.AddLeave(n1,2)
	POLICY.AddLeave(n1,3)

	POLICY.AddLeave(0,4)   
	POLICY.AddLeave(n2,0)
	POLICY.AddLeave(n2,1)
  
    //MASTER
	//initialization de la master key pour la central authority

	MASTER := new (MASTERKEY)
	MASTER.Init()
   
    // pk => G1, h ealpha 
// generer la pubkey pour encrypt


   // ******************************************************
   //KEYGEN
   // ******************************************************

   SK, PK := POLICY.GenKEYPAIR(MASTER,[]string{"","","","","auditor"})
   SK2, _ := POLICY.GenKEYPAIR(MASTER,[]string{"companyA","manager","","",""})
   SK3, _ := POLICY.GenKEYPAIR(MASTER,[]string{"","","companyB","manager",""})
   SK4, _ := POLICY.GenKEYPAIR(MASTER,[]string{"","","companyB","employe",""})
   SK5, _ := POLICY.GenKEYPAIR(MASTER,[]string{"","","companyB","employe","auditor"})
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
   fmt.Println()
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)


   m = POLICY.Decrypt(SK,CipherData)  
   	fmt.Println(SK.user_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")


    m = POLICY.Decrypt(SK2,CipherData)  
	fmt.Println(SK2.user_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
  
    m = POLICY.Decrypt(SK3,CipherData)  
   	fmt.Println(SK3.user_attr)  
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
  
  m = POLICY.Decrypt(SK4,CipherData)  
   fmt.Println(SK4.user_attr)
   
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")

   m = POLICY.Decrypt(SK5,CipherData)  
   fmt.Println(SK5.user_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
 
}
