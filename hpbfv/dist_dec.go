package hpbfv

import (
	"spdz-go/rlwe"

	"spdz-go/ring"
	"spdz-go/utils"

	"crypto/rand"
	"math/big"
)

type DistributedDecryptor struct {
	Decryptor
	buff *ring.Poly
	sk   *rlwe.SecretKey

	prng       utils.PRNG
	noiseBytes int
}

func NewDistributedDecryptor(params Parameters, sk *rlwe.SecretKey) (dec *DistributedDecryptor) {
	dec = new(DistributedDecryptor)
	dec.Decryptor = *NewDecryptor(params, sk)
	dec.buff = params.RingQ().NewPoly()
	dec.sk = sk

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	dec.prng = prng
	dec.noiseBytes = 16
	return
}

func (dec *DistributedDecryptor) PartialDecrypt(ct *Ciphertext) *ring.Poly {
	level := ct.Level()

	ringQ := dec.params.RingQ()
	share := ringQ.NewPolyLvl(level)

	if ct.Degree() != 1 {
		panic("cannot PartialDecrypt: ct.Degree() != 1")
	}

	ringQ.NTTLazyLvl(level, ct.Value[1], share)

	ringQ.MulCoeffsMontgomeryLvl(level, share, dec.sk.Value.Q, share)

	ringQ.InvNTTLvl(level, share, share)

	dec.addNoise(share)

	return share
}

func (dec *DistributedDecryptor) JointDecrypt(ct *Ciphertext, shares []*ring.Poly, ptOut *Plaintext) {
	ringQ := dec.params.RingQ()

	level := utils.MinInt(ct.Level(), ptOut.Level())

	ptOut.Value.Resize(level)

	ptOut.MetaData = ct.MetaData

	acc := ringQ.NewPolyLvl(level)

	for _, share := range shares {
		ringQ.AddLvl(level, acc, share, acc)
	}

	ringQ.NTTLvl(level, acc, acc)

	buff := ringQ.NewPolyLvl(level)
	ringQ.NTTLazyLvl(level, ct.Value[0], buff)
	ringQ.AddLvl(level, acc, buff, ptOut.Value)

	ringQ.ReduceLvl(level, ptOut.Value, ptOut.Value)

	ringQ.InvNTTLvl(level, ptOut.Value, ptOut.Value)
}

func (dec *DistributedDecryptor) JointDecryptNew(ct *Ciphertext, shares []*ring.Poly) (ptOut *Plaintext) {
	ptOut = NewPlaintext(dec.params)
	dec.JointDecrypt(ct, shares, ptOut)
	return
}

func (dec *DistributedDecryptor) JointDecryptToMsg(ct *Ciphertext, shares []*ring.Poly, msgOut *Message) {
	pt := dec.JointDecryptNew(ct, shares)
	dec.dcd.Decode(pt, msgOut)
}

func (dec *DistributedDecryptor) JointDecryptToMsgNew(ct *Ciphertext, shares []*ring.Poly) (msgOut *Message) {
	msgOut = NewMessage(dec.params)
	dec.JointDecryptToMsg(ct, shares, msgOut)
	return
}

func (dec *DistributedDecryptor) addNoise(pol *ring.Poly) {
	ringQ := dec.params.RingQ()
	buf := make([]byte, dec.noiseBytes)

	for j := 0; j < ringQ.N; j++ {
		_, err := rand.Read(buf)
		if err != nil {
			panic(err)
		}

		noiseBig := new(big.Int).SetBytes(buf)

		for i, qi := range ringQ.Modulus {
			noiseMod := new(big.Int).Mod(noiseBig, new(big.Int).SetUint64(qi)).Uint64()

			sum := pol.Coeffs[i][j] + noiseMod
			if sum >= qi {
				sum -= qi
			}

			pol.Coeffs[i][j] = sum
		}
	}
}
