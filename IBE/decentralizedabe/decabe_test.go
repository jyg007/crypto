package main 

import ( "testing"
	util "decabe/utils"
		hex "encoding/hex"
		"fmt"
		"bytes"
)




func TestAorB(t* testing.T) {
	rnd := util.GetRand()

	// Cas de 4 sociétés gérant chacun un attribut.
	// Les deux premieres sociétés peuvent lire la donnée mais pas la troisième.
	// on fait le test avec quatre employés, ceux autorisés et les autres
	A := [][]int{{1},{1},{0},{0}}
	p := []int{0,1,2,3}
	n := len(A)
	c := []int{1}  //(tels que Sum cxAx = 0) par utilisateur  , Ax correspond à l unique clé qu'il possède
	

	// Authority Setup/	n := 4


	ATTRIBUTE_MASTER := GenMasterKeys(n)


	// on va faire ligne par ligne

	//A := [][]int{{1},{1},{1}}


	// maps row of the matrices to the attributes


    M := util.RandFP(rnd)
    fmt.Println("Key pour l encodage: ",hex.EncodeToString(util.Hash_AES_Key(M)))

	CipheredData := Encrypt(M,A,p,ATTRIBUTE_MASTER)

	//	MatrixMul(A,p,v,1)
	GID := "jeanyves.girard@ibm.com"

	//Keygen for a user gid and an attribute i
    var K1,K2,K3,K4 []*USERKEY
   /* for i:=0;i<n;i++ {
	  	K[i] = KEYGEN([]byte(GID),ATTRIBUTE_MASTER[i].SK,i)
	}*/
	// l organisation qui gere l attribyt 2 signe
	// Simulons 4 utilisateurs
	K1 = append(K1, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[0].SK,0) )
	K2 = append(K2, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[1].SK,1) )
	K3 = append(K3, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[2].SK,2) )
	K4 = append(K4, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[3].SK,3) )

	// Decrypt
	U := DECRYPT(CipheredData, K1,GID,p,c)
	fmt.Println("Key pour le decodage AES pour user1: ",hex.EncodeToString(util.Hash_AES_Key(U)))

	U = DECRYPT(CipheredData, K2,GID,p,c)
	fmt.Println("Key pour le decodage AES pour user2: ",hex.EncodeToString(util.Hash_AES_Key(U)))

	U = DECRYPT(CipheredData, K3,GID,p,c)
	fmt.Println("Key pour le decodage AES pour user3 ",hex.EncodeToString(util.Hash_AES_Key(U)))

	U = DECRYPT(CipheredData, K4,GID,p,c)
	fmt.Println("Key pour le decodage AES pour suer4 ",hex.EncodeToString(util.Hash_AES_Key(U)))

}

func TestManagerEtDeuxEntreprisesSeulement(t* testing.T) {
	rnd := util.GetRand()

	// Modèle 3 sociétés, un attribut Manager et un Attribut Employé
	// Cas de 4 sociétés gérant chacun un attribut.
	// Les deux premieres sociétés peuvent lire la donnée mais pas la troisième.
	// on fait le test avec quatre employés, ceux autorisés et les autres
	A := [][]int{{0,-1},{1,1},{0,0},{0,-1},{1,1},{0,0},{0,0},{0,0},{0,0}}
	p := []int{0,1,2,3,4,5,6,7,8}
	n := len(A)
	c := []int{1,1,1}  //(tels que Sum cxAx = (1,0,0,0..0)) par utilisateur  , Ax correspond à l unique clé qu'il possède
	

	// Authority Setup/	n := 4

	t.Log("Génération des master Keys")
	ATTRIBUTE_MASTER := GenMasterKeys(n)

	// on va faire ligne par ligne

	//A := [][]int{{1},{1},{1}}


	// maps row of the matrices to the attributes


    M := util.RandFP(rnd)
    aeskey := util.Hash_AES_Key(M)
    t.Log("Key pour l encodage: ",hex.EncodeToString(aeskey),"\n")


	CipheredData := Encrypt(M,A,p,ATTRIBUTE_MASTER)



	//	MatrixMul(A,p,v,1)
	GID1 := "jyg1@ibm.com"
	GID2 := "jeanyves.girard2@ibm.com"
	GID3 := "jeanyves.girard3@ibm.com"
	GID4 := "jeanyves.girard4@ibm.com"

	//Keygen for a user gid and an attribute i
    var K1,K2,K3,K4 []*USERKEY
   /* for i:=0;i<n;i++ {
	  	K[i] = KEYGEN([]byte(GID),ATTRIBUTE_MASTER[i].SK,i)
	}*/
	// l organisation qui gere l attribyt 2 signe
	// Simulons 4 utilisateurs
	// le dernier paramètre correspond à un nom d attribut
	K1 = append(K1, KEYGEN([]byte(GID1),ATTRIBUTE_MASTER[0].SK,0) )  //Airbus
	K1 = append(K1, KEYGEN([]byte(GID1),ATTRIBUTE_MASTER[1].SK,1) )  //Manager

	K2 = append(K2, KEYGEN([]byte(GID2),ATTRIBUTE_MASTER[0].SK,0) )   //Airbus
	K2 = append(K2, KEYGEN([]byte(GID2),ATTRIBUTE_MASTER[2].SK,2) )   //Employé 

	K3 = append(K3, KEYGEN([]byte(GID3),ATTRIBUTE_MASTER[3].SK,3) )   //IBM
	K3 = append(K3, KEYGEN([]byte(GID3),ATTRIBUTE_MASTER[4].SK,4) )   //Manager 

	K4 = append(K4, KEYGEN([]byte(GID3),ATTRIBUTE_MASTER[6].SK,6) )   //HP
	K4 = append(K4, KEYGEN([]byte(GID3),ATTRIBUTE_MASTER[8].SK,8) )   //Employe 



	//K4 = append(K4, KEYGEN([]byte(GID),ATTRIBUTE_MASTER[3].SK,3) )

	// Decrypt

	t.Log("User Airbus et Manager")
	decryptedaeskey := util.Hash_AES_Key(DECRYPT(CipheredData, K1,GID1,p,c))
	t.Log(hex.EncodeToString(decryptedaeskey),"\n")
	if !bytes.Equal(decryptedaeskey,aeskey)  {
		t.Error()
	} 

	t.Log("User Airbus mais employé")
	U := DECRYPT(CipheredData, K2,GID2,p,c)
	t.Log(hex.EncodeToString(util.Hash_AES_Key(U)),"\n")

	t.Log("User IBM et Manager")
	decryptedaeskey = util.Hash_AES_Key(DECRYPT(CipheredData, K3,GID3,p,c))
	t.Log(hex.EncodeToString(decryptedaeskey),"\n")
	if !bytes.Equal(decryptedaeskey,aeskey)  {
		t.Error()
	} 

	t.Log("User HP et employé")
	U = DECRYPT(CipheredData, K4,GID4,p,c)
	t.Log(hex.EncodeToString(util.Hash_AES_Key(U)),"\n")


	t.Log("User Airbus et Manager mais le GID n est pas bon")
	decryptedaeskey = util.Hash_AES_Key(DECRYPT(CipheredData, K1,GID2,p,c))
	t.Log(hex.EncodeToString(decryptedaeskey),"\n")
	if bytes.Equal(decryptedaeskey,aeskey)  {
		t.Error()
	} 

	K1 = nil
	K1 = append(K1, KEYGEN([]byte(GID1),ATTRIBUTE_MASTER[0].SK,0) )  //Airbus
	K1 = append(K1, KEYGEN([]byte(GID1),ATTRIBUTE_MASTER[1].SK,1) )  //Manager
	K1 = append(K1, KEYGEN([]byte(GID1),ATTRIBUTE_MASTER[2].SK,2) )   //Employe

	t.Log("User Airbus et Manager et Employé !")
	decryptedaeskey = util.Hash_AES_Key(DECRYPT(CipheredData, K1,GID1,p,c))
	t.Log(hex.EncodeToString(decryptedaeskey),"\n")
	if !bytes.Equal(decryptedaeskey,aeskey)  {
		t.Error()
	} 

}