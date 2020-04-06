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


	
type node struct {
    parent int  // index of the parent node
    leaves []int
    threshold  int     	//threshold 1 pour OR et nombre de leafs si AND
    attr int     // index de l attribut teste ici
    x []*curve.BIG
    y []*curve.BIG
}


func (n *node) Init(rnd *amcl.RAND ,parent int, leaves []int , threshold int, attr int)  {
	n.parent = parent
	n.leaves = leaves
	n.threshold = threshold
	n.attr = attr

	n.x = make([]*curve.BIG, threshold )
	n.y = make([]*curve.BIG, threshold )
	//valeur en zero defini par rapport aux parent

	if (threshold > 1 ) {
		for  j:= 1;j< threshold;j++ {
			n.x[j] = curve.NewBIGint(j)
			n.y[j] = RandModOrder(rnd)
		}
	}
}


func Modsub(a, b, m *curve.BIG) *curve.BIG {
        return curve.Modadd(a, curve.Modneg(b, m), m)
}


func (n *node) Lagrange_Interpolate(x *curve.BIG) (*curve.BIG) {
	est := curve.NewBIGint(0)
	for i := 0; i < len(n.x); i++ {
		prod := curve.NewBIGcopy(n.y[i])
		tmp1 := curve.NewBIG()
		tmp2 := curve.NewBIG()
		
		for j := 0; j < len(n.x); j++ {
			if i != j {
			//	fmt.Println(x.ToString())
			//	fmt.Println(j)
			//	fmt.Println(n.x[j].ToString())
				
				tmp1 = Modsub(x,n.x[j],GroupOrder)  
				tmp2 = Modsub(n.x[i],n.x[j],GroupOrder)
				tmp2.Invmodp(GroupOrder)
				prod = curve.Modmul(prod,tmp1,GroupOrder)
				prod = curve.Modmul(prod,tmp2,GroupOrder)
			}
		}
		est = curve.Modadd(prod,est,GroupOrder)
	}

	return est
}
 

func  getq_zero(n *[]*node, s  *curve.BIG ,   k int, x int)  ( *curve.BIG) {
	fmt.Println("-- ",k," ",x)
	if (x ==0) {
		if ( k ==0 ) {
			// en fait jamais appelé ?
			fmt.Println("k =>" ,(*(*n)[k]).threshold)
			//(*(*n)[k]).x[0] = curve.NewBIGint(0)
			//(*(*n)[k]).y[0] = s
			return s	
		}
		fmt.Println("setting 0 for k ",k)
		(*(*n)[k]).x[0] = curve.NewBIGint(0)
		(*(*n)[k]).y[0] = getq_zero(n, s, (*(*n)[k]).parent,k)
		return (*(*n)[k]).y[0]
	}
	X := curve.NewBIGint(x)
	return (*(*n)[k]).Lagrange_Interpolate(X)
}


func main() {
   	rnd := GetRand()
    
	// construction de la policy
	policy := make([]*node,3)
	for i:=0 ; i< 3 ; i++ {
		policy[i] = new(node)
	}
	//  parent   | leaves | threeshold  | attributes #
	// Threashold how leaves should be true
	policy[0].Init(rnd, -1, []int{1 , 2} , 1,-1 )
		
	s := RandModOrder(rnd)   // je pense propre à la policy	
	policy[0].x[0] = curve.NewBIGint(0)
	policy[0].y[0] = s
	
	policy[1].Init(rnd,  0, []int{} , 1 , 0 )
	policy[2].Init(rnd,  0, []int{} , 1 , 1  )


   fmt.Println("s:",s.ToString())

   q10 := getq_zero(&policy,s,1,0)
   fmt.Println("q10:",q10.ToString())

   q20 := getq_zero(&policy,s,2,0)
   fmt.Println("q20:",q20.ToString())
   
   fmt.Println()
 //  os.Exit(2)

    // Modelisation polynomiqle (voir lecture 14) de condition a ou b (simple...)
    // on part ici dans un test a1 OR a2 
    //  Le polynome est donc de degre 0 (condition Or sur les racine de polynome) .  soit de la forme qR(x) = i  , on a dont qR(0) = s qui force i = s
    //  on a deux conditions pour test a1 et q2  q1(0)=qR(r1) soit forcement s et de meme q2(0)=qR(r2) soit forcement s egamenet
    //   donc q1(x)=q2(x)=qR(x)=s  

  
    // Definition de la policy  => l arbre a deux attributs testé et on cree le tableau att qui nous donne l index de l attribut tester pour chaque feuille de l arbre
    // Donc dans un cas attr1 ou attr2 on a
 	leaves_nb:=2

/*    leaves_att := make([]int,leaves_nb)
    leaves_att[0] = policy[1].attr
    leaves_att[1] = policy[2].attr
*/
    leaves_nodes := make([]int,leaves_nb)
    
    leaves_nodes[0] = 1
    leaves_nodes[1] = 2


    //nombre d attribut
	attr_nb :=2

	//tableau à deux attribut que l on definit avec une valeur plutot qu un bit
	// a represente les attributes de celui qui veut accesder à la preuve
	a :=make([]string,attr_nb)

    a[0]= "employeibm"
    a[1] = "employeairbus"


    // pareil mais utilisé pour la création de la preuve
	attr_proof :=make([]string,attr_nb)

    attr_proof[0]= "employeibm"
    attr_proof[1] = "employeairbus"


    //MASTER
	//initialization de la master key pour la central authority

    alpha := RandModOrder(rnd)
	beta := RandModOrder(rnd)
    h := GenG1.Mul(beta)
    ealpha := GenGT.Pow(alpha)
   

    // pk => G1, h ealpha 



   // ******************************************************
   //KEYGEN
   // ******************************************************
   
   var i int
  // s := RandModOrder(rnd)   // je pense propre à la policy
   
   Dj := make([]*curve.ECP,attr_nb)
   Djprime := make([]*curve.ECP8,attr_nb)
 
   // (r, r1,r2) defini par utilisateur
   r := RandModOrder(rnd)

   r_attr := make([]*curve.BIG,attr_nb)
   for i = 0 ; i < attr_nb ; i++ {
   	  r_attr[i] = RandModOrder(rnd)
   }

   tmp1 := curve.Modadd(alpha,r, GroupOrder )
   betainv := curve.NewBIGcopy(beta)
   betainv.Invmodp(GroupOrder)
   puis := curve.Modmul(tmp1,betainv,GroupOrder)
   D := GenG2.Mul(puis)

   // q1(0) = s et q2(0) = s ici, sinon voir doc et poly de Lagrange pour interpolation
 
   // creation de D pour tous les attributs

    for i = 0 ; i < attr_nb ; i++ {
 	  tmp6 := curve.ECP_mapit([]byte(a[i])).Mul(r_attr[i])
   	  tmp7 := GenG1.Mul(r)
      tmp7.Add(tmp6)
      Dj[i] = curve.NewECP()
      Dj[i].Copy(tmp7)
      Djprime[i] = GenG2.Mul(r_attr[i])
   }
 


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
   
   Cj := make([]*curve.ECP8,leaves_nb)
   Cjprime := make([]*curve.ECP,leaves_nb)

   // ici on parcourt les feuilles et non les listes d attributs.  Exemple un attribut peut revenir deux fois.
   for i = 0 ; i < leaves_nb ; i++ {
   	   q0 := getq_zero(&policy,s,leaves_nodes[i],0)
   	   fmt.Println(attr_proof[policy[leaves_nodes[i]].attr])
   	   fmt.Println(q0.ToString())
       Cjprime[i] = curve.ECP_mapit([]byte(attr_proof[policy[leaves_nodes[i]].attr])).Mul(q0)
       Cj[i] = GenG2.Mul(s)
   }
   

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


   // on n utilise que le premier indice.
   A := curve.NewFP48copy(eCD1)
   A.Inverse()

   T1 := curve.Fexp(curve.Ate(D,C))
   T1.Mul(A)
 //  fmt.Println("\naa =========",T1.ToString())

   T1.Inverse()

   Cprime.Mul(T1)


   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(Cprime)))


 

}
