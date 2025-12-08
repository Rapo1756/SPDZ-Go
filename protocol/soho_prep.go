package protocol

import (
	"spdz-go/hpbfv"
	"spdz-go/rlwe"
	"spdz-go/utils"
)

type SohoParty struct {
	id int

	params hpbfv.Parameters

	keygen *hpbfv.PartialKeyGenerator

	sk   *rlwe.SecretKey
	ppk  *rlwe.PublicKey
	jpk  *rlwe.PublicKey
	prlk *hpbfv.RelinearizationKey
	jrlk *hpbfv.RelinearizationKey

	prng utils.PRNG

	ecd  *hpbfv.Encoder
	enc  *hpbfv.Encryptor
	eval *hpbfv.MEvaluator
	ddec *hpbfv.DistributedDecryptor

	triples []*Triple
}

func NewSohoParty(id int, params hpbfv.Parameters, crs []byte) *SohoParty {
	keygen := hpbfv.NewPartialKeyGenerator(params, crs)
	sk, ppk, prlk := keygen.GenKeys()

	triples := make([]*Triple, 0)

	prng, err := utils.NewPRNG()
	if err != nil {
		panic("cannot NewDistDec: PRNG cannot be generated")
	}

	return &SohoParty{
		id:      id,
		params:  params,
		keygen:  keygen,
		sk:      sk,
		ppk:     ppk,
		prlk:    prlk,
		prng:    prng,
		ecd:     hpbfv.NewEncoder(params),
		eval:    hpbfv.NewMEvaluator(params),
		ddec:    hpbfv.NewDistributedDecryptor(params, sk),
		triples: triples,
	}
}

func (party *SohoParty) Setup(ppks []*rlwe.PublicKey, prlks []*hpbfv.RelinearizationKey) {
	party.jpk, party.jrlk = party.keygen.AggregateKeys(ppks, prlks)
	party.enc = hpbfv.NewEncryptor(party.params, party.jpk)
}

func (party *SohoParty) BufferTriplesRoundOne() (a, b *hpbfv.Message, ca, cb *hpbfv.Ciphertext) {
	a = party.SampleUniformModT()
	b = party.SampleUniformModT()
	
	ca = party.enc.EncryptMsgNew(a)
	cb = party.enc.EncryptMsgNew(b)
	return
}

func (party *SohoParty) BufferTriplesRoundTwo(cas, cbs []*hpbfv.Ciphertext, noiseBits int) (*hpbfv.Message, *hpbfv.Ciphertext, *hpbfv.DistDecShare) {
	sumCa := party.Aggregate(cas)
	sumCb := party.Aggregate(cbs)

	// Compute c = a*b
	cc := party.eval.MulAndRelinNew(sumCa, sumCb, party.jrlk)

	s, dsh := party.ReshareInit(cc, noiseBits)

	return s, cc, dsh
}

func (party *SohoParty) FinalizeTriple(a, b *hpbfv.Message, cc *hpbfv.Ciphertext, s *hpbfv.Message, dshs []*hpbfv.DistDecShare) {
	c := party.ReshareFinalize(cc, dshs, s)

	for i := 0; i < party.params.Slots(); i++ {
		ai := a.Value[i]
		bi := b.Value[i]
		ci := c.Value[i]

		party.triples = append(party.triples, &Triple{
			A: ai,
			B: bi,
			C: ci,
		})
	}
}
