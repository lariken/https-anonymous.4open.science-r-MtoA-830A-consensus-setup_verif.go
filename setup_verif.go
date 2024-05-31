package main

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"crypto/sha256"
	"time"
//	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
//	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	curve2  "github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc"
	fr2 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)


func main() {
	repeat:=10
	t:=64
	l:=7
	v:=7
	computeHashes:=true
	fmt.Println("t=",t)
	fmt.Println("l=",l)
	fmt.Println("n=",2*(3*t+1)*l)
	fmt.Println("computeHashes=",computeHashes)
	_,_,G1,G2:=curve.Generators()
	_,G:=curve2.Generators()

	t1:=benchmarkN(benchmark_PoP_RY_all, t, l, G1, G2, computeHashes, repeat)
	t2:=benchmarkN(benchmark_PoP_RY_one, t, l, G1, G2, computeHashes, repeat)
	t11:=benchmarkN(benchmark_PoP_RY_allFast, t, l, G1, G2,  computeHashes,  repeat)
	t21:=benchmarkN(benchmark_PoP_RY_oneFast, t, l, G1, G2, computeHashes,  repeat)
	t3:=benchmarkN(benchmark_our_PoP_all, t, l, G1, G2, computeHashes, repeat)
	t4:=benchmarkN(benchmark_our_PoP_one, t, l, G1, G2, computeHashes, repeat)
	t5:=benchmarkN(benchmark_BDN, t, l, G1, G2, computeHashes, repeat)
	t6:=benchmarkN(benchmark_multiSign, t, v, G1, G2, computeHashes, repeat)
	t7:=benchmarkN(benchmark_BLS, t, v, G1, G2, computeHashes, repeat)
	t8:=benchmark_Schnorr(t, G, repeat)
	bool9,t9 := test_blsdleq(G1,repeat)

	fmt.Println("benchmark PoP_RY_all",t1)
	fmt.Println("benchmark PoP_RY_one",t2)
	fmt.Println("benchmark PoP_RY_allFast",t11)
	fmt.Println("benchmark PoP_RY_oneFast",t21)
	fmt.Println("benchmark our_PoP_all",t3)
	fmt.Println("benchmark our_PoP_one",t4)
	fmt.Println("benchmark BDN",t5)
	fmt.Println("benchmark multiSign",t6)
	fmt.Println("benchmark BLS",t7)
	fmt.Println("benchmark Schnorr",t8)
	fmt.Println("benchmark blsdleq", bool9)
	fmt.Println("correctness blsdleq", t9)
}




func benchmarkN(benchmarkOne func(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration, t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool, repeat int) float64 {
  var sum float64

  for i := 0; i < repeat; i++ {
  	sum += benchmarkOne(t, l, G1, G2, computeHashes).Seconds()
  }
  return sum / float64(repeat) * 1000.0 // millisecndes
}


//Creates random vector with N entries in fr
func create_vectorFr(N int)[]fr.Element {
	c:=make([]fr.Element, N)
	for i:=range(c){
		(&c[i]).SetRandom()
	}
	return c		
}

//Creates random vector with N entries in fr for sec256pk1
func create_vectorFr2(N int)[]fr2.Element {
	c:=make([]fr2.Element, N)
	for i:=range(c){
		(&c[i]).SetRandom()
	}
	return c		
}

//Creates random vector with N entries in big.Int
func create_vectorBig(N int)[]big.Int {
	c:=make([]big.Int, N)
	for i:=range(c){
		randInt, _ := rand.Int(rand.Reader, fr.Modulus())
		(&c[i]).Set(randInt)
	}
	return c		
}


//Creates vector with N entries in G1Affine by multiplying generator G1 of G1Affine with random coefficients
func create_vectorG1(N int, G1 curve.G1Affine)[]curve.G1Affine {
	coeffs:=create_vectorFr(N) //vector with N entries in Fr
	return curve.BatchScalarMultiplicationG1(&G1,coeffs) //returns (coeffs[i].G) for i=1...N
}

//Creates vector with N entries in G2Affine by multiplying generator G2 of G2Affine with random coefficients
func create_vectorG2(N int, G2 curve.G2Affine)[]curve.G2Affine {
	coeffs:=create_vectorFr(N) //vector with N entries in Fr
	return curve.BatchScalarMultiplicationG2(&G2,coeffs) //returns (coeffs[i].G) for i=1...N
}

//Creates vector with N entries in G1Affine for sec256pk1 by multiplying generator G of G1Affine with random coefficients
func create_vectorG(N int, G curve2.G1Affine)[]curve2.G1Affine {
	coeffs:=create_vectorFr2(N) //vector with N entries in Fr
	return curve2.BatchScalarMultiplicationG1(&G,coeffs) //returns (coeffs[i].G) for i=1...N
}

//PoP verification of RY [Ristenpart, Yilek]
func PoP_RY_verif(S []curve.G1Affine, H []curve.G1Affine, X []curve.G2Affine, G2 curve.G2Affine) bool{
		res:=true
		GG2:=[]curve.G2Affine{G2}
		for i:=range(S) {
			A,_:=curve.Pair([]curve.G1Affine{S[i]},GG2) 
			B,_:=curve.Pair([]curve.G1Affine{H[i]},[]curve.G2Affine{X[i]})
			if A != B {
				res=false
			}
		}
		return res	
}

//same as above but with batch verification, see CHO [Camenisch, Hohenberger, Ostergaard]
//checks whether  pair(Sum e_i.S[i] , G2) == pair(e_i.Hash(X_i) , X_i)

func PoP_RY_verifFast(S []curve.G1Affine, H []curve.G1Affine, Xp []curve.G1Affine, X []curve.G2Affine, e []fr.Element, G1 curve.G1Affine, G2 curve.G2Affine, ComputeHashes bool) bool{
		var eS curve.G1Affine
		var b big.Int
		dst:=[]byte("PoPRY-<10>")
		eH:=make([]curve.G1Affine,len(H))
		for i:=range(S){
			(&S[i]).IsInSubGroup()
		}
		for i:=range(X){
			(&X[i]).IsInSubGroup()
		}
		if ComputeHashes ==true {
			for i:=range(X){
				A:=(&X[i]).Bytes()
				Hi,_:=curve.HashToG1(A[:],dst)
				(&H[i]).Set(&Hi)
			}
		}
		for i:=range(H){
			(&eH[i]).ScalarMultiplication(&H[i],(&e[i]).BigInt(&b))
		}
		(&eS).MultiExp(S,e,ecc.MultiExpConfig{})
		A,_:=curve.Pair([]curve.G1Affine{eS},[]curve.G2Affine{G2})
		B,_:=curve.Pair(eH,X)
		return (A==B)
}

//benchmark of RY PoP verification for n=3t+1 participants at once
func benchmark_PoP_RY_all(t int,l int,G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
		n:=3*t+1
		N:=2*n*l
		S:=create_vectorG1(N,G1)
		H:=create_vectorG1(N,G1)
		X:=create_vectorG2(N,G2)
		start:=time.Now()
		PoP_RY_verif(S, H, X, G2)
		return time.Since(start)
}

//benchmark for one participant
func benchmark_PoP_RY_one(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
		N:=2*l
		S:=create_vectorG1(N,G1)
		H:=create_vectorG1(N,G1)
		X:=create_vectorG2(N,G2)
		start:=time.Now()
		PoP_RY_verif(S, H, X, G2)
		return time.Since(start)
}

//same as above, n participants, with CHO batch verification
func benchmark_PoP_RY_allFast(t int,l int,G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
		n:=3*t+1
		N:=2*n*l
		S:=create_vectorG1(N,G1)
		H:=create_vectorG1(N,G1)
		Xp:=create_vectorG1(N,G1)
		X:=create_vectorG2(N,G2)
		e:=create_vectorFr(N)
		start:=time.Now()
		PoP_RY_verifFast(S, H, Xp, X, e, G1, G2, computeHashes)
		return time.Since(start)
}

//same as above, 1 participant, with CHO batch verification
func benchmark_PoP_RY_oneFast(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
		N:=2*l
		S:=create_vectorG1(N,G1)
		H:=create_vectorG1(N,G1)
		X:=create_vectorG2(N,G2)
		Xp:=create_vectorG1(N,G1)
		e:=create_vectorFr(N)
		start:=time.Now()
		PoP_RY_verifFast(S, H, Xp, X, e, G1, G2, computeHashes)
		return time.Since(start)
}

//hash of a slice of points
func hashPoints(Pts []curve.G2Affine, dst []byte) fr.Element{
	PointsBytes:=make([]byte,0)
	for i:=range(Pts){
		A:=(&Pts[i]).Bytes()
		PointsBytes=append(PointsBytes,A[:]...)
	}
	hfr,_:=fr.Hash(PointsBytes,dst,1)
	return hfr[0]
}


//our PoP verification
//checks whether  (Sum e_i.z_i)G.2 == Sum e_i.R[i] + Sum (e_i.c_i).X[i]
func our_PoP_verif(e []fr.Element, z []fr.Element, c []fr.Element, R []curve.G2Affine, X []curve.G2Affine, G2 curve.G2Affine, ComputeHashes bool) bool{
	coeffs:=make([]fr.Element, len(X)) //list of coefficients in MultiExp
	Pts:=make([]curve.G2Affine, len(X)) //list of points in MultiExp
	var ez fr.Element //e[i]*z[i]
	var sumez fr.Element //sum_ e[i]*z[i]
	var ec fr.Element //e[i]*c[i]
	var Res, Res2 curve.G2Affine
	var scal big.Int // the big.Int counterpart of sumez
	for i:=range(X){
		if (&X[i]).IsInSubGroup() == false {
			return false
		}
		if ComputeHashes == true {
			dst:=[]byte("PoPRL-<10>")
			hfr:=hashPoints([]curve.G2Affine{X[i],X[i],R[i]},dst)
			(&c[i]).Set(&hfr)
		}
		(&ez).Mul(&e[i],&z[i])
		(&sumez).Add(&sumez,&ez)
		(&ec).Mul(&e[i],&c[i])
		coeffs=append(coeffs,e[i])
		coeffs=append(coeffs,ec)
		Pts=append(Pts,R[i])
		Pts=append(Pts,X[i])
	}
	(&Res).MultiExp(Pts,coeffs,ecc.MultiExpConfig{})
	(&sumez).BigInt(&scal)
	(&Res2).ScalarMultiplication(&G2,&scal)
	return (&Res).Equal(&Res2) 
}







//benchmark of our PoP verification for n=3t+1 participants
func benchmark_our_PoP_all(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, ComputeHashes bool) time.Duration{
		n:=3*t+1
		N:=2*n*l
		e:=create_vectorFr(N)
		z:=create_vectorFr(N)
		c:=create_vectorFr(N)
		X:=create_vectorG2(N,G2)
		R:=create_vectorG2(N,G2)
		start:=time.Now()
		our_PoP_verif(e,z,c,R,X,G2, ComputeHashes)
		return time.Since(start)
}

//benchmark of our PoP verification for 1 participant
func benchmark_our_PoP_one(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, ComputeHashes bool) time.Duration{
		N:=2*l
		e:=create_vectorFr(N)
		z:=create_vectorFr(N)
		c:=create_vectorFr(N)
		X:=create_vectorG2(N,G2)
		R:=create_vectorG2(N,G2)
		start:=time.Now()
		our_PoP_verif(e,z,c,X,R,G2, ComputeHashes)
		return time.Since(start)
}


//BDN setup
//Computes Hash(X,X[i]).X[i] for all i
//Checks if each X[i] is in the right subgroup
//when newkeys is true, only checks if X[0],...,X[newkeynumber-1] are in the right subgroup
func setup_BDN_verif(h []big.Int, X[]curve.G2Affine, G1 curve.G1Affine, G2 curve.G2Affine, newkeys bool, newkeynumber int, computeHashes bool)bool {
	res:=true
	if computeHashes == true {
		hashfunc:=sha256.New()
		XBytes:=make([]byte,0)
		XiBytes:=make([][]byte,len(X))
		for i:=range(X){
			A:=(&X[i]).Bytes()
			XiBytes[i]=A[:]
			XBytes=append(XBytes,XiBytes[i]...)
		}
		hashfunc.Write(XBytes)
		for i:=range(h){
			hashi:=hashfunc
			hashi.Write(XiBytes[i])
			h[i].SetBytes(hashi.Sum(nil))
		}
	}
	for i:=range(X){
		if (newkeys == false) || (i<newkeynumber){
			if ((&X[i]).IsInSubGroup())==false{
				res=false
			}
		}
		(&X[i]).ScalarMultiplication(&X[i],&h[i])
	}
	return res
}

//benchmark of BDN setup
func benchmark_BDN(t int,l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
	newkeynumber:=14
	newkeys:=true
	n:=3*t+1
	N:=2*n*l
	var h fr.Element
	(&h).SetRandom()	
	hB:=create_vectorBig(N)
	X:=create_vectorG2(N,G2)
	start:=time.Now()
	setup_BDN_verif(hB,X,G1,G2,newkeys,newkeynumber,computeHashes)
	return time.Since(start)
}


//multi signature verification
//checks the following:
// S is in the right subgroup
// pair(S,G2)=pair(Hash(m),sum X[i])
func multiSign(S curve.G1Affine, X []curve.G2Affine, H curve.G1Affine, G2 curve.G2Affine,  m []byte, computeHashes bool) bool{
	var SumX curve.G2Affine
	dst:=[]byte("MultiSignRL<10>")
	if computeHashes == true{
		H,_ =curve.HashToG1(m,dst)
	}
	var SumJac curve.G2Jac
	for i:=range(X){
		(&SumJac).AddMixed(&X[i])
	}
	(&SumX).FromJacobian(&SumJac)
	A,_:=curve.Pair([]curve.G1Affine{S},[]curve.G2Affine{G2})
	B,_:=curve.Pair([]curve.G1Affine{H},[]curve.G2Affine{SumX})
	return (A == B) && (&S).IsInSubGroup()
}


//benchmark of multi signature 
func benchmark_multiSign(t int, v int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
	n:=2*t+1
	N:=n*v
	S:=create_vectorG1(1,G1)
	X:=create_vectorG2(N,G2)
	msg:=make([]byte,128)
	rand.Read(msg)
	var c fr.Element
	(&c).SetRandom()
	var cc big.Int
	(&c).BigInt(&cc)
	var H curve.G1Affine
	(&H).ScalarMultiplication(&G1,&cc)
	start:=time.Now()
	multiSign(S[0],X,H,G2,msg,computeHashes)
	return time.Since(start)
}


//BLS aggregation
//checks the following:
// S is in the right subgroup
//pair(S,G2)=pair(Hash(m),X)
func aggregate_BLS(S curve.G1Affine, H []curve.G1Affine, X []curve.G2Affine, G2 curve.G2Affine, m []byte, computeHashes bool) bool{
	if computeHashes == true{
		dst:=[]byte("BLSagg<10>")
		for i:=range(H){
			H[i],_=curve.HashToG1(m,dst)
		}
	}
	A,_:=curve.Pair([]curve.G1Affine{S},[]curve.G2Affine{G2})
	B,_:=curve.Pair(H,X)
	return (A == B) && (&S).IsInSubGroup()
}


//benchmark of BLS aggregation
func benchmark_BLS(t int, l int, G1 curve.G1Affine, G2 curve.G2Affine, computeHashes bool) time.Duration{
	ni:=2*t+1
	Ni:=2*ni
	S:=create_vectorG1(1,G1)
	X:=create_vectorG2(Ni,G2)
	H:=create_vectorG1(Ni,G1)
	msg:=make([]byte,128)
	rand.Read(msg)
	start:=time.Now()
	aggregate_BLS(S[0],H,X,G2,msg,computeHashes)
	return time.Since(start)		
}


//Batch verification of n=2t+1 signatures
func Schnorr_verif(n int, G curve2.G1Affine, X[] curve2.G1Affine, R []curve2.G1Affine, z []fr2.Element, e []fr2.Element, m [][]byte) bool{
	dst:=[]byte("Schnorrsig<10>")
	var ez, ec, sumez fr2.Element
	var Sum curve2.G1Affine
	coeffs:=make([]fr2.Element, 2*n+1)
	Pts:=make([]curve2.G1Affine, 2*n+1)
	conf:=ecc.MultiExpConfig{}
	for i:=range(X){
		A:=(&X[i]).RawBytes()
		byt:=A[:]
		byt=append(byt,m[i]...)
		B:=(&R[i]).RawBytes()
		byt=append(byt,B[:]...)
		c,_:=fr2.Hash(byt,dst,1)
		(&ez).Mul(&e[i],&z[i])
		(&sumez).Add(&sumez,&ez)
		(&ec).Mul(&e[i],&c[0])
		(&coeffs[2*i]).Set(&e[i])
		(&coeffs[2*i+1]).Set(&ec)
		(&Pts[2*i]).Set(&R[i])
		(&Pts[2*i+1]).Set(&X[i])
	}
	(&Pts[2*n]).Set(&G)
	(&coeffs[2*n]).Set((&sumez).Neg(&sumez))
	(&Sum).MultiExp(Pts,coeffs,conf)
	return (&Sum).IsInfinity()
}


//benchmark of Schnorr verification on faster secp256k1 curve
func benchmark_Schnorr(t int, G curve2.G1Affine, repeat int) float64{
	var sum time.Duration
	for rep:=0; rep<repeat;rep++{
		n:=2*t+1
		X:=create_vectorG(n,G)
		R:=create_vectorG(n,G)
		e:=create_vectorFr2(n)
		z:=create_vectorFr2(n)
		msg:=make([][]byte,0)
		for i:=0; i<n; i++{
			a:=make([]byte, 128)
			rand.Read(a)
			msg=append(msg,a)	
		}
		start:= time.Now()
		Schnorr_verif(n, G, X, R, z, e, msg)
		sum+= time.Since(start)
	}
	return sum.Seconds()/float64(repeat)*1000
}



// BLS signature + Chaum-Pedersen DLEQ
func blsdleq(G curve.G1Affine, s fr.Element, X curve.G1Affine, m []byte) (fr.Element, fr.Element, curve.G1Affine){
	dst:=[]byte("BLSDLEQ-<10>")
	var M, S, Xr, Mr curve.G1Affine
	var r,z fr.Element
	M,_=curve.HashToG1(m,dst)
	conf:=ecc.MultiExpConfig{}
	(&S).MultiExp([]curve.G1Affine{M},[]fr.Element{s},conf)
	(&r).SetRandom()
	(&Xr).MultiExp([]curve.G1Affine{G},[]fr.Element{r},conf)
	(&Mr).MultiExp([]curve.G1Affine{M},[]fr.Element{r},conf)
	HashBytes:=make([]byte,0)
	XB:=(&X).Bytes()
	MB:=(&M).Bytes()
	XrB:=(&Xr).Bytes()
	MrB:=(&Mr).Bytes()
	HashBytes=append(HashBytes,XB[:]...)	
	HashBytes=append(HashBytes,MB[:]...)	
	HashBytes=append(HashBytes,XrB[:]...)	
	HashBytes=append(HashBytes,MrB[:]...)
	c,_:=fr.Hash(HashBytes,dst,1)
	(&z).Mul(&c[0],&s)
	(&z).Sub(&r,&z)
	return c[0],z,S
}


// BLS signature + Chaum-Pedersen DLEQ verification
func blsdleq_verif(G curve.G1Affine, S curve.G1Affine, X curve.G1Affine, c fr.Element, z fr.Element, m []byte) bool{
	dst:=[]byte("BLSDLEQ-<10>")
	var Mcheck, Xr, Mr curve.G1Affine
	conf:=ecc.MultiExpConfig{}
	Mcheck,_=curve.HashToG1(m,dst)
	PointsX:=[]curve.G1Affine{G, X}
	PointsM:=[]curve.G1Affine{Mcheck, S}
	Scalars:=[]fr.Element{z,c}
	(&Xr).MultiExp(PointsX,Scalars,conf)
	(&Mr).MultiExp(PointsM,Scalars,conf)
	HashBytes:=make([]byte,0)
	XB:=(&X).Bytes()
	MB:=(&Mcheck).Bytes()
	XrB:=(&Xr).Bytes()
	MrB:=(&Mr).Bytes()
	HashBytes=append(HashBytes,XB[:]...)	
	HashBytes=append(HashBytes,MB[:]...)	
	HashBytes=append(HashBytes,XrB[:]...)	
	HashBytes=append(HashBytes,MrB[:]...)
	ccheck,_:=fr.Hash(HashBytes,dst,1)
	return ((&c).Equal(&ccheck[0])) && (&S).IsInSubGroup()
}


func test_blsdleq(G curve.G1Affine, repeat int) (float64, bool){
	var s,c,z fr.Element
	var X,S curve.G1Affine
	conf:=ecc.MultiExpConfig{}
	(&s).SetRandom()
	(&X).MultiExp([]curve.G1Affine{G},[]fr.Element{s},conf)
	buf := make([]byte, 128)
	rand.Read(buf)
	m:=buf[:]
	c,z,S = blsdleq(G,s,X,m)
	start:=time.Now()
	for i:=0;i<repeat;i++{
		blsdleq_verif(G, S, X, c, z, m) 
	}
	end:=time.Since(start)	
	res:=blsdleq_verif(G, S, X, c, z, m)
	return end.Seconds()/float64(repeat)*1000,res
}







