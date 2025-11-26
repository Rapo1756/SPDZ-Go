package hpbfv

import (
	"spdz-go/rlwe"

	"spdz-go/ring"
	"spdz-go/rlwe/ringqp"
	"spdz-go/utils"
)

type RelinearizationKey struct {
	BD rlwe.GadgetCiphertext
	V  rlwe.GadgetCiphertext
}

type PartialKeyGenerator struct {
	params Parameters

	sk *rlwe.SecretKey

	buffQ [2]*ring.Poly

	gaussianSampler *ring.GaussianSampler
	ternarySampler  *ring.TernarySampler

	prng utils.PRNG

	A [][]ringqp.Poly
	U [][]ringqp.Poly
}

func NewRelinearizationKey(params rlwe.Parameters, levelQ, levelP int) *RelinearizationKey {
	rlk := new(RelinearizationKey)
	rlk.BD = rlwe.NewSwitchingKey(params, levelQ, levelP).GadgetCiphertext
	rlk.V = rlwe.NewSwitchingKey(params, levelQ, levelP).GadgetCiphertext
	return rlk
}

// NewPartialKeyGenerator creates a KeyGenerator instance from the spdz-go parameters,
// using the provided common reference string.
// Note: The ct.Value[1] are same only if it is generated at the same time,
// i.e., each party should call GenPublicKey only once per common reference string.
func NewPartialKeyGenerator(params Parameters, crs []byte) *PartialKeyGenerator {
	crsGenerator, err := utils.NewKeyedPRNG(crs)
	if err != nil {
		panic(err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	sk := rlwe.NewSecretKey(params.Parameters)

	ringQ := params.RingQ()

	gaussianSampler := ring.NewGaussianSampler(prng, params.RingQ(), params.Sigma(), int(6*params.Sigma()))
	ternarySampler := ring.NewTernarySamplerWithHammingWeight(prng, params.RingQ(), params.HammingWeight(), false)
	uniformSampler := ringqp.NewUniformSampler(crsGenerator, *params.RingQP())

	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1

	a := make([][]ringqp.Poly, params.DecompRNS(levelQ, levelP))
	for i := 0; i < len(a); i++ {
		a[i] = make([]ringqp.Poly, params.DecompPw2(levelQ, levelP))
		for j := 0; j < len(a[i]); j++ {
			a[i][j] = params.RingQP().NewPoly()
			uniformSampler.ReadLvl(levelQ, levelP, a[i][j])
		}
	}
	u := make([][]ringqp.Poly, params.DecompRNS(levelQ, levelP))
	for i := 0; i < len(u); i++ {
		u[i] = make([]ringqp.Poly, params.DecompPw2(levelQ, levelP))
		for j := 0; j < len(u[i]); j++ {
			u[i][j] = params.RingQP().NewPoly()
			uniformSampler.ReadLvl(levelQ, levelP, u[i][j])
		}
	}
	return &PartialKeyGenerator{
		params:          params,
		sk:              sk,
		buffQ:           [2]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()},
		prng:            prng,
		gaussianSampler: gaussianSampler,
		ternarySampler:  ternarySampler,
		A:               a,
		U:               u,
	}
}

func (keygen *PartialKeyGenerator) GenSecretKey() (sk *rlwe.SecretKey) {
	sk = new(rlwe.SecretKey)
	ringQP := keygen.params.RingQP()
	sk.Value = ringQP.NewPoly()
	levelQ, levelP := sk.LevelQ(), sk.LevelP()
	keygen.ternarySampler.ReadLvl(levelQ, sk.Value.Q)

	ringQP.NTTLvl(levelQ, levelP, sk.Value, sk.Value)
	ringQP.MFormLvl(levelQ, levelP, sk.Value, sk.Value)

	return
}

func (keygen *PartialKeyGenerator) GenPartialKeys(sk *rlwe.SecretKey) (pk *rlwe.PublicKey, rlk *RelinearizationKey) {
	params := keygen.params.Parameters
	ringQP := keygen.params.RingQP()
	levelQ := keygen.params.QCount() - 1
	levelP := keygen.params.PCount() - 1

	// Generate Relinearization Key
	rlk = NewRelinearizationKey(params, levelQ, levelP)

	// Sample random r
	r := keygen.GenSecretKey()

	// Calculate d = - a * r + s * g + e'
	for i := 0; i < len(rlk.BD.Value); i++ {
		for j := 0; j < len(rlk.BD.Value[0]); j++ {
			// Copy a to rlk.BD.Value[i][j].Value[1]
			keygen.encryptZeroQP(rlk.BD.Value[i][j].Value[0], keygen.A[i][j], r)
		}
	}
	rlwe.AddPolyTimesGadgetVectorToGadgetCiphertext(sk.Value.Q,
		[]rlwe.GadgetCiphertext{rlk.BD}, *ringQP, params.Pow2Base(), keygen.buffQ[0])

	// Calculate b = - a * s + e
	for i := 0; i < len(rlk.BD.Value); i++ {
		for j := 0; j < len(rlk.BD.Value[0]); j++ {
			ringQP.CopyLvl(levelQ, levelP, rlk.BD.Value[i][j].Value[0], rlk.BD.Value[i][j].Value[1])
			keygen.encryptZeroQP(rlk.BD.Value[i][j].Value[0], keygen.A[i][j], sk)
		}
	}

	// Calculate v = - u * s - r * g + e"
	for i := 0; i < len(rlk.V.Value); i++ {
		for j := 0; j < len(rlk.V.Value[0]); j++ {
			// Copy u to rlk.V.Value[i][j].Value[1]
			ringQP.CopyLvl(levelQ, levelP, keygen.U[i][j], rlk.V.Value[i][j].Value[1])
			keygen.encryptZeroQP(rlk.V.Value[i][j].Value[0], rlk.V.Value[i][j].Value[1], sk)
		}
	}
	keygen.params.RingQP().NegLvl(levelQ, levelP, r.Value, r.Value)
	rlwe.AddPolyTimesGadgetVectorToGadgetCiphertext(r.Value.Q,
		[]rlwe.GadgetCiphertext{rlk.V}, *ringQP, params.Pow2Base(), keygen.buffQ[0])

	// Generate Public Key
	pk = rlwe.NewPublicKey(params)

	// pk = rlk.B[0][0]
	pk.Value[0] = rlk.BD.Value[0][0].Value[0]
	pk.Value[1] = keygen.A[0][0]
	return
}

func (keygen *PartialKeyGenerator) GenKeys() (sk *rlwe.SecretKey, pk *rlwe.PublicKey, rlk *RelinearizationKey) {
	sk = keygen.GenSecretKey()
	pk, rlk = keygen.GenPartialKeys(sk)
	return
}

func (keygen *PartialKeyGenerator) encryptZeroQP(c0, c1 ringqp.Poly, sk *rlwe.SecretKey) {
	levelQ, levelP := c0.LevelQ(), c1.LevelP()
	ringQP := keygen.params.RingQP()

	keygen.gaussianSampler.ReadLvl(levelQ, c0.Q)
	if levelP != -1 {
		ringQP.ExtendBasisSmallNormAndCenter(c0.Q, levelP, nil, c0.P)
	}

	ringQP.NTTLvl(levelQ, levelP, c0, c0)
	ringQP.MFormLvl(levelQ, levelP, c0, c0)

	ringQP.MulCoeffsMontgomeryAndSubLvl(levelQ, levelP, c1, sk.Value, c0)
}

func (keygen *PartialKeyGenerator) AggregateKeys(pks []*rlwe.PublicKey, rlks []*RelinearizationKey) (jpk *rlwe.PublicKey, jrlk *RelinearizationKey) {
	ringQP := keygen.params.RingQP()

	levelQ := pks[0].Value[0].LevelQ()
	levelP := pks[0].Value[0].LevelP()

	// Aggregate Relinearization Keys
	jrlk = NewRelinearizationKey(keygen.params.Parameters, levelQ, levelP)	

	for i := 0; i < len(jrlk.BD.Value); i++ {
		for j := 0; j < len(jrlk.BD.Value[0]); j++ {
			ringQP.CopyLvl(levelQ, levelP, rlks[0].BD.Value[i][j].Value[0], jrlk.BD.Value[i][j].Value[0])
			ringQP.CopyLvl(levelQ, levelP, rlks[0].BD.Value[i][j].Value[1], jrlk.BD.Value[i][j].Value[1])

			ringQP.CopyLvl(levelQ, levelP, rlks[0].V.Value[i][j].Value[0], jrlk.V.Value[i][j].Value[0])
			ringQP.CopyLvl(levelQ, levelP, rlks[0].V.Value[i][j].Value[1], jrlk.V.Value[i][j].Value[1])

			for k := 1; k < len(rlks); k++ {
				ringQP.AddLvl(levelQ, levelP, jrlk.BD.Value[i][j].Value[0], rlks[k].BD.Value[i][j].Value[0], jrlk.BD.Value[i][j].Value[0])
				ringQP.AddLvl(levelQ, levelP, jrlk.BD.Value[i][j].Value[1], rlks[k].BD.Value[i][j].Value[1], jrlk.BD.Value[i][j].Value[1])

				if !rlks[k].V.Value[i][j].Value[1].Equals(keygen.U[i][j]) {
					panic("AggregateRelinKeys: mismatch in common reference string")
				}
				ringQP.AddLvl(levelQ, levelP, jrlk.V.Value[i][j].Value[0], rlks[k].V.Value[i][j].Value[0], jrlk.V.Value[i][j].Value[0])
			}
		}
	}

	// Aggregate Public Keys
	jpk = rlwe.NewPublicKey(keygen.params.Parameters)
	jpk.IsNTT = true
	jpk.IsMontgomery = true
	ringQP.CopyLvl(levelQ, levelP, pks[0].Value[0], jpk.Value[0])
	ringQP.CopyLvl(levelQ, levelP, pks[0].Value[1], jpk.Value[1])

	for i := 1; i < len(pks); i++ {
		if pks[i].Value[0].LevelQ() != levelQ || pks[i].Value[0].LevelP() != levelP {
			panic("AggregatePublicKeys: mismatch in ciphertext levels")
		}
		if !pks[i].Value[1].Equals(keygen.A[0][0]) {
			panic("AggregatePublicKeys: mismatch in common reference string")
		}
		ringQP.AddLvl(levelQ, levelP, jpk.Value[0], pks[i].Value[0], jpk.Value[0])
	}

	return jpk, jrlk
}
