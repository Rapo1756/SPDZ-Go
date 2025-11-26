package protocol

import (
	"spdz-go/hpbfv"
	"spdz-go/ring"
	"spdz-go/utils"

	"math/big"
)

type DistDecShare struct {
	*ring.Poly
}

// SampleUniformModT samples a message with coefficients uniformly random in [0, t)
func SampleUniformModT(params hpbfv.Parameters, prng utils.PRNG) *hpbfv.Message {
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
			_, err := prng.Read(buf)
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

func (p *SohoParty) SampleUniformModTAndEncrypt() (*hpbfv.Message, *hpbfv.Ciphertext) {
	msg := SampleUniformModT(p.params, p.prng)
	ct := p.enc.EncryptMsgNew(msg)
	return msg, ct
}

func (p *SohoParty) Aggregate(cts []*hpbfv.Ciphertext) *hpbfv.Ciphertext {
	sumCt := hpbfv.NewCiphertext(p.params, 1)
	for _, ct := range cts {
		p.eval.Add(sumCt, ct, sumCt)
	}
	return sumCt
}

func (p *SohoParty) AggregateAndAdd(ctIn *hpbfv.Ciphertext, cts []*hpbfv.Ciphertext) *hpbfv.Ciphertext {
	sumCt := p.Aggregate(cts)
	p.eval.Add(ctIn, sumCt, sumCt)
	return sumCt
}

func (p *SohoParty) Reshare(ctIn *hpbfv.Ciphertext, shares []*DistDecShare, msg *hpbfv.Message) *hpbfv.Message {
	if p.id != 0 {
		negMsg := hpbfv.NewMessage(p.params)
		t := p.params.T()
		for i := 0; i < p.params.Slots(); i++ {
			negMsg.Value[i].Sub(t, msg.Value[i])
		}
		return negMsg
	}

	sharesPolys := make([]*ring.Poly, len(shares))
	for i, share := range shares {
		sharesPolys[i] = share.Poly
	}

	msgDec := p.ddec.JointDecryptToMsgNew(ctIn, sharesPolys)

	for i := 0; i < p.params.Slots(); i++ {
		msgDec.Value[i].Sub(msgDec.Value[i], msg.Value[i])
		msgDec.Value[i].Mod(msgDec.Value[i], p.params.T())
	}

	return msgDec
}
