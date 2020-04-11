package main

//Identity-based encryption [Boneh and Franklin 2001]


import (
	"fmt"
	pol "cpabe/policy"
	util "cpabe/utils"
	hex "encoding/hex"
)

const OR=1
const AND=2

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


	POLICY2 := new(pol.Policy)
	POLICY2.Init(3,[]string{"companyA","manager", "companyB", "manager","auditor"})
	POLICY2.AddLeave(0,4)  
	POLICY2.AddLeave(0,0)  
	POLICY2.AddLeave(0,1)
  
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
   SK2, _ := POLICY.GenKEYPAIR(MASTER,[]string{"companyA","manager","","","auditor"})
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
   fmt.Println("Key pour l encodage: ",hex.EncodeToString(util.Hash_AES_Key(m)))

   CipherData := POLICY.Encrypt(PK,m)
   CipherData2 := POLICY2.Encrypt(PK,m)

   // ******************************************************
   // DECRYPT
   // ******************************************************
   fmt.Println()
   // à coupler à de l AES qui se sert de m (utiliser un sha3 shake pour generer la cle AES)


   m = POLICY.Decrypt(SK,CipherData)  
   fmt.Println(SK.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(util.Hash_AES_Key(m)),"\n")

   m2 := POLICY2.Decrypt(SK,CipherData2)  
   fmt.Println("Key pour le decodage policy 2: ",hex.EncodeToString(util.Hash_AES_Key(m2)),"\n")



    m = POLICY.Decrypt(SK2,CipherData)  
	fmt.Println(SK2.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(util.Hash_AES_Key(m)),"\n")
  
   m2 = POLICY2.Decrypt(SK2,CipherData2)  
   fmt.Println("Key pour le decodage policy 2: ",hex.EncodeToString(util.Hash_AES_Key(m2)),"\n")



    m = POLICY.Decrypt(SK3,CipherData)  
   	fmt.Println(SK3.User_attr)  
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(util.Hash_AES_Key(m)),"\n")
  
   m = POLICY.Decrypt(SK4,CipherData)  
   fmt.Println(SK4.User_attr)
   
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(util.Hash_AES_Key(m)),"\n")

   m = POLICY.Decrypt(SK5,CipherData)  
   fmt.Println(SK5.User_attr)
   fmt.Println("Key pour le decodage: ",hex.EncodeToString(util.Hash_AES_Key(m)),"\n")
 
}
