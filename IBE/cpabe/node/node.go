package node


import (
	curve "cpabe/miracl/core/go/core/BLS48581"
	util "cpabe/utils"
)

type NODE struct {
    Parent int  // index of the parent node
    Leaves []int
    Threshold  int     	//threshold 1 pour OR et nombre de leafs si AND
    Attr int     // index de l attribut teste ici
    X []*curve.BIG   // represente les points du polynome au noeud en fonction du threshold
    Y []*curve.BIG
}

func (n *NODE) SetChildren(children []int , threshold int) {
	rnd := util.GetRand()
	 n.Leaves = children
	 n.Threshold = threshold
	for i := len(n.X) ; i<threshold;i++ {
	   	n.X = append(n.X,curve.NewBIGint(10+i))
	   	n.Y = append(n.Y,util.RandModOrder(rnd))
	}
}

//********************************************************************************************************************************************************************
//********************************************************************************************************************************************************************
func (n *NODE) Lagrange_Interpolate(x *curve.BIG) (*curve.BIG) {
	est := curve.NewBIGint(0)
	for i := 0; i < len(n.X); i++ {
	//	fmt.Println(n.y[i])
		prod := curve.NewBIGcopy(n.Y[i])
		// if x is nul alors il faut retrouver q[0]

		for j := 0; j < len(n.X); j++ {
			if i != j {
		
				tmp1 := util.Modsub(x,n.X[j],util.GroupOrder)  
				tmp2 := util.Modsub(n.X[i],n.X[j],util.GroupOrder)
				tmp2.Invmodp(util.GroupOrder)
				prod = curve.Modmul(prod,tmp1,util.GroupOrder)
				prod = curve.Modmul(prod,tmp2,util.GroupOrder)
			}
		}
		est = curve.Modadd(prod,est,util.GroupOrder)
	}
	return est
}