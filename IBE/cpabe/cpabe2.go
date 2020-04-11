package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	pol "cpabe/policy"
	util "cpabe/utils"
	 hex "encoding/hex"
//	"crypto/rand"
//	amcl "cpabe/miracl/core/go/core"
	curve "cpabe/miracl/core/go/core/BLS48581"
	"golang.org/x/crypto/sha3"
)




const OR=1
const AND=2






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
	





//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************

func main() {

	POLICY := new(pol.Policy)
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

	MASTER := new (pol.MASTERKEY)
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

   rnd := util.GetRand()
   m := util.RandFP(rnd)
   fmt.Println("Key pour l encodage: ",hex.EncodeToString(Hash_AES_Key(m)))

   CipherData := POLICY.Encrypt(PK,m)

   // ******************************************************
   // DECRYPT
   // ******************************************************
   fmt.Println()
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)


   m = POLICY.Decrypt(SK,CipherData)  
   	fmt.Println(SK.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")


    m = POLICY.Decrypt(SK2,CipherData)  
	fmt.Println(SK2.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
  
    m = POLICY.Decrypt(SK3,CipherData)  
   	fmt.Println(SK3.User_attr)  
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
  
  m = POLICY.Decrypt(SK4,CipherData)  
   fmt.Println(SK4.User_attr)
   
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")

   m = POLICY.Decrypt(SK5,CipherData)  
   fmt.Println(SK5.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(Hash_AES_Key(m)),"\n")
 
}
