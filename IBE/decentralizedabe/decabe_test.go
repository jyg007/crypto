package main 

import ( "testing"
	util "decabe/utils"
		hex "encoding/hex"
		"fmt"
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