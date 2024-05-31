

//benchmark of our PoP verification for n=3t+1 participants with BCLS speedup
func benchmark_our_PoP_allFast(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, ComputeHashes bool) time.Duration{
		n:=3*t+1
		N:=2*n*l
		e:=create_vectorFr(N)
		z:=create_vectorFr(N)
		c:=create_vectorFr(N)
		Xp:=create_vectorG1(N,G1)
		X:=create_vectorG2(1,G2)
		R:=create_vectorG1(N,G1)
		vecOne:=make([]fr.Element,N)
		for i:=range(vecOne){
			(&vecOne[i]).SetOne()
		}
		start:=time.Now()
		our_PoP_verifFast(e,z,c,R,Xp,X[0],G1,G2,vecOne,ComputeHashes)
		return time.Since(start)
}


//benchmark of our PoP verification for 1 participant with BCLS speedup
func benchmark_our_PoP_oneFast(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, ComputeHashes bool) time.Duration{
		N:=2*l
		e:=create_vectorFr(N)
		z:=create_vectorFr(N)
		c:=create_vectorFr(N)
		Xp:=create_vectorG1(N,G1)
		X:=create_vectorG2(1,G2)
		R:=create_vectorG1(N,G1)
		vecOne:=make([]fr.Element,N)
		for i:=range(vecOne){
			(&vecOne[i]).SetOne()
		}
		start:=time.Now()
		our_PoP_verifFast(e,z,c,R,Xp,X[0],G1,G2,vecOne,ComputeHashes)
		return time.Since(start)
}


//our PoP verification with speedup using auxiliary public keys Xp, in order to compute MultiExp in G1 instead of G2, see BCLS [Burdges, Ciobotaru, Lavasani, Stewart] 
func our_PoP_verifFast(e []fr.Element, z []fr.Element, c []fr.Element, R []curve.G1Affine, Xp []curve.G1Affine, SumX curve.G2Affine, G1 curve.G1Affine, G2 curve.G2Affine, vecOne []fr.Element, ComputeHashes bool) bool{
	coeffs:=make([]fr.Element, len(Xp)) //list of coefficients in MultiExp
	Pts:=make([]curve.G1Affine, len(Xp)) //list of points in MultiExp
	var SumXp curve.G1Affine
	conf:=ecc.MultiExpConfig{}
	(&SumXp).MultiExp(Xp,vecOne[:len(Xp)],conf) //SumXp = sum of Xp[i]
	var mone fr.Element
	dst:=[]byte("PoPRLF<10>")
	(&mone).SetOne()
	(&mone).Neg(&mone)
	var ez fr.Element //e[i]*z[i]
	var ec fr.Element //e[i]*c[i]
	var Res curve.G1Affine
	for i:=range(Xp){
		(&Xp[i]).IsInSubGroup()
		if ComputeHashes == true {
			A:=(&Xp[i]).Bytes()
			B:=(&R[i]).Bytes()
			bytestohash:=append(A[:],A[:]...)
			bytestohash=append(bytestohash,B[:]...)
			hfr,_:=fr.Hash(bytestohash,dst,1)
			(&c[i]).Set(&hfr[0])
		}
		(&ez).Mul(&e[i],&z[i])
		(&ec).Mul(&e[i],&c[i])
		(&ec).Neg(&ec)
		coeffs=append(coeffs,ez)
		coeffs=append(coeffs,mone)
		coeffs=append(coeffs,ec)
		Pts=append(Pts,G1)
		Pts=append(Pts,R[i])
		Pts=append(Pts,Xp[i])
	}
	(&Res).MultiExp(Pts,coeffs,ecc.MultiExpConfig{})
	Check1,_:=curve.Pair([]curve.G1Affine{SumXp},[]curve.G2Affine{G2})
	Check2,_:=curve.Pair([]curve.G1Affine{G1},[]curve.G2Affine{SumX})
	return ((&Res).IsInfinity()) && (Check1 == Check2)
}


//multi signature using BCLS speedup
func multiSignFast(S curve.G1Affine, Xp []curve.G1Affine, SumX curve.G2Affine, vecOne []fr.Element, H curve.G1Affine, G1 curve.G1Affine, G2 curve.G2Affine) bool{
	var SumXp curve.G1Affine
	conf:=ecc.MultiExpConfig{}
	(&SumXp).MultiExp(Xp,vecOne[:len(Xp)],conf)
	Check1,_:=curve.Pair([]curve.G1Affine{SumXp},[]curve.G2Affine{G2})
	Check2,_:=curve.Pair([]curve.G1Affine{G1},[]curve.G2Affine{SumX})
	A,_:=curve.Pair([]curve.G1Affine{S},[]curve.G2Affine{G2})
	B,_:=curve.Pair([]curve.G1Affine{H},[]curve.G2Affine{SumX})
	return (A == B) && (Check1 == Check2) && (&S).IsInSubGroup()
}



//benchmark of multi signature using BCLS speedup
func benchmark_multiSignFast(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
	n:=3*t+1
	N:=n*l
	S:=create_vectorG1(1,G1)
	Xp:=create_vectorG1(N,G1)
	X:=create_vectorG2(1,G2)
	vecOne:=make([]fr.Element,N)
	var c fr.Element
	(&c).SetRandom()
	var cc big.Int
	(&c).BigInt(&cc)
	var H curve.G1Affine
	(&H).ScalarMultiplication(&G1,&cc)
	start:=time.Now()
	multiSignFast(S[0],Xp,X[0],vecOne,H,G1,G2)
	return time.Since(start)
}



//BLS aggregation in case there is only one value in H
func aggregate_BLS_oneH(S curve.G1Affine, H curve.G1Affine, X []curve.G2Affine, vecOne []fr.Element, G2 curve.G2Affine) bool{
	var SumX curve.G2Affine
	(&SumX).MultiExp(X,vecOne[:len(X)],ecc.MultiExpConfig{})
	A,_:=curve.Pair([]curve.G1Affine{S},[]curve.G2Affine{G2})
	B,_:=curve.Pair([]curve.G1Affine{H},[]curve.G2Affine{SumX})
	return (A == B) && (&S).IsInSubGroup()
}



//benchmark of BLS aggregation in case there is only one value in H
func benchmark_BLS_oneH(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
	ni:=2*t+1
	Ni:=2*ni
	S:=create_vectorG1(1,G1)
	X:=create_vectorG2(Ni,G2)
	H:=create_vectorG1(1,G1)
	vecOne:=make([]fr.Element,Ni)
	for i:=range(vecOne){
		(&vecOne[i]).SetOne()
	}
	start:=time.Now()
	aggregate_BLS_oneH(S[0],H[0],X,vecOne,G2)
	return time.Since(start)		
}


