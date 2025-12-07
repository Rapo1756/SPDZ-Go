package protocol

import (
	"spdz-go/hpbfv"
	"spdz-go/rlwe"
	"spdz-go/utils"

	"math/big"
)

type HemiParty struct {
	id int

	params hpbfv.Parameters

	keygen hpbfv.KeyGenerator

	sks []*rlwe.SecretKey // sks[j] = sk_{id, j}
	pks []*rlwe.PublicKey // pks[j] = pk_{j, id}

	ecd      *hpbfv.Encoder
	eval     *hpbfv.Evaluator
	encSelfs []*hpbfv.Encryptor
	encs     []*hpbfv.Encryptor
	decs     []*hpbfv.Decryptor

	prng utils.PRNG

	triples []*Triple
}

func NewHemiParty(id int, params hpbfv.Parameters, numParties int) *HemiParty {
	keygen := hpbfv.NewKeyGenerator(params)
	prng, err := utils.NewPRNG()
	if err != nil {
		panic("cannot NewHemiParty: PRNG cannot be generated")
	}

	return &HemiParty{
		id:       id,
		params:   params,
		keygen:   keygen,
		sks:      make([]*rlwe.SecretKey, numParties),
		pks:      make([]*rlwe.PublicKey, numParties),
		prng:     prng,
		ecd:      hpbfv.NewEncoder(params),
		encSelfs: make([]*hpbfv.Encryptor, numParties),
		encs:     make([]*hpbfv.Encryptor, numParties),
		decs:     make([]*hpbfv.Decryptor, numParties),
		eval:     hpbfv.NewEvaluator(params),
		triples:  make([]*Triple, 0),
	}
}

func (party *HemiParty) InitSetup(numParties int) []*rlwe.PublicKey {
	pks := make([]*rlwe.PublicKey, numParties)

	for j := 0; j < numParties; j++ {
		if j == party.id {
			continue
		}
		sk, pk := party.keygen.GenKeyPair()
		party.sks[j] = sk
		pks[j] = pk
		party.encSelfs[j] = hpbfv.NewEncryptor(party.params, pk)
		party.decs[j] = hpbfv.NewDecryptor(party.params, sk)
	}
	return pks
}

func (party *HemiParty) FinalizeSetup(pks []*rlwe.PublicKey) {
	party.pks = pks
	for j := 0; j < len(pks); j++ {
		if j == party.id {
			continue
		}
		party.encs[j] = hpbfv.NewEncryptor(party.params, pks[j])
	}
}

// SampleUniformModT samples a message with coefficients uniformly random in [0, t)
func (p *HemiParty) SampleUniformModT() *hpbfv.Message {
	params := p.params
	// Rejection sampling
	samples := make([]*big.Int, params.Slots())
	t := params.T()
	bitLen := t.BitLen()
	byteLen := (bitLen + 7) / 8
	mask := big.NewInt(1)
	mask.Lsh(mask, uint(bitLen))
	mask.Sub(mask, big.NewInt(1))

	for i := 0; i < params.Slots(); i++ {
		for {
			buf := make([]byte, byteLen)
			_, err := p.prng.Read(buf)
			if err != nil {
				panic("cannot SampleUniformModT: PRNG read error")
			}
			sample := new(big.Int).SetBytes(buf)
			sample.And(sample, mask)
			if sample.Cmp(t) < 0 {
				samples[i] = sample
				break
			}
		}
	}
	msg := hpbfv.NewMessage(params)
	for i := 0; i < params.Slots(); i++ {
		msg.Value[i] = samples[i]
	}
	return msg
}

func (party *HemiParty) SampleAandB() (*hpbfv.Message, *hpbfv.Message) {
	a := party.SampleUniformModT()
	b := party.SampleUniformModT()
	return a, b
}

func (party *HemiParty) PairwiseRoundOne(a *hpbfv.Message, dst int) *hpbfv.Ciphertext {
	ct := party.encSelfs[dst].EncryptMsgNew(a)
	return ct
}

func (party *HemiParty) PairwiseRoundTwo(ctIn *hpbfv.Ciphertext, b *hpbfv.Message, src int) (*hpbfv.Message, *hpbfv.Ciphertext) {
	eij := party.SampleUniformModT()
	encEij := party.encs[src].EncryptMsgNew(eij)

	ptB := party.ecd.EncodeNew(b)

	cij := party.eval.PlaintextMulNew(ptB, ctIn)
	party.eval.Sub(cij, encEij, cij)

	return eij, cij
}

func (party *HemiParty) Finalize(a, b *hpbfv.Message, ejis []*hpbfv.Message, cijs []*hpbfv.Ciphertext) {
	// Multiply a and b
	ab := hpbfv.NewMessage(party.params)
	for i := 0; i < party.params.Slots(); i++ {
		ab.Value[i].Mul(a.Value[i], b.Value[i])
	}
	for j, cij := range cijs {
		if j == party.id {
			continue
		}
		// Decrypt cij
		dij := party.decs[j].DecryptToMsgNew(cij)

		// Add e_{i,j}
		for i := 0; i < party.params.Slots(); i++ {
			ab.Value[i].Add(ab.Value[i], dij.Value[i])
			ab.Value[i].Add(ab.Value[i], ejis[j].Value[i])
		}
	}

	for i := 0; i < party.params.Slots(); i++ {
		ab.Value[i].Mod(ab.Value[i], party.params.T())
		party.triples = append(party.triples, &Triple{
			A: a.Value[i],
			B: b.Value[i],
			C: ab.Value[i],
		})
	}
}
