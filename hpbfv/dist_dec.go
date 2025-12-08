package hpbfv

import (
	"spdz-go/rlwe"

	"spdz-go/ring"
	"spdz-go/utils"

	"math/big"
)

type DistributedDecryptor struct {
	Decryptor
	buff *ring.Poly
	sk   *rlwe.SecretKey

	prng utils.PRNG
}

type DistDecShare struct {
	*ring.Poly
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
	return
}

func (dec *DistributedDecryptor) PartialDecrypt(ct *Ciphertext, noiseBits int) *DistDecShare {
	level := ct.Level()

	ringQ := dec.params.RingQ()
	share := ringQ.NewPolyLvl(level)

	if ct.Degree() != 1 {
		panic("cannot PartialDecrypt: ct.Degree() != 1")
	}

	ringQ.NTTLazyLvl(level, ct.Value[1], share)

	ringQ.MulCoeffsMontgomeryLvl(level, share, dec.sk.Value.Q, share)

	ringQ.InvNTTLvl(level, share, share)
	dec.addNoise(share, noiseBits)

	return &DistDecShare{share}
}

func (dec *DistributedDecryptor) PartialDecryptNew(ct *Ciphertext, noiseBits int) *DistDecShare {
	return dec.PartialDecrypt(ct, noiseBits)
}

func (dec *DistributedDecryptor) JointDecrypt(ct *Ciphertext, shares []*DistDecShare, ptOut *Plaintext) {
	ringQ := dec.params.RingQ()

	level := utils.MinInt(ct.Level(), ptOut.Level())

	ptOut.Value.Resize(level)

	ptOut.MetaData = ct.MetaData

	acc := ringQ.NewPolyLvl(level)

	for _, share := range shares {
		ringQ.AddLvl(level, acc, share.Poly, acc)
	}

	ringQ.NTTLvl(level, acc, acc)

	buff := ringQ.NewPolyLvl(level)
	ringQ.NTTLazyLvl(level, ct.Value[0], buff)
	ringQ.AddLvl(level, acc, buff, ptOut.Value)

	ringQ.ReduceLvl(level, ptOut.Value, ptOut.Value)

	ringQ.InvNTTLvl(level, ptOut.Value, ptOut.Value)
}

func (dec *DistributedDecryptor) JointDecryptNew(ct *Ciphertext, shares []*DistDecShare) (ptOut *Plaintext) {
	ptOut = NewPlaintext(dec.params)
	dec.JointDecrypt(ct, shares, ptOut)
	return
}

func (dec *DistributedDecryptor) JointDecryptToMsg(ct *Ciphertext, shares []*DistDecShare, msgOut *Message) {
	pt := dec.JointDecryptNew(ct, shares)
	dec.dcd.Decode(pt, msgOut)
}

func (dec *DistributedDecryptor) JointDecryptToMsgNew(ct *Ciphertext, shares []*DistDecShare) (msgOut *Message) {
	msgOut = NewMessage(dec.params)
	dec.JointDecryptToMsg(ct, shares, msgOut)
	return
}

// The logic is for RNS representation
func (dec *DistributedDecryptor) addNoise(pol *ring.Poly, noiseBits int) {
	ringQ := dec.params.RingQ()
	buf := make([]byte, (noiseBits+7)/8)

	for j := 0; j < ringQ.N; j++ {
		_, err := dec.prng.Read(buf)
		if err != nil {
			panic(err)
		}

		noiseBig := new(big.Int).SetBytes(buf)

		// Mask the noise to the desired bit-length
		mask := new(big.Int).Lsh(big.NewInt(1), uint(noiseBits))
		mask.Sub(mask, big.NewInt(1))
		noiseBig.And(noiseBig, mask)

		// Add the noise to each modulus
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
