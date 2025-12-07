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

func (dec *DistributedDecryptor) PartialDecrypt(ct *Ciphertext, noise interface{}) *ring.Poly {
	level := ct.Level()

	ringQ := dec.params.RingQ()
	share := ringQ.NewPolyLvl(level)

	if ct.Degree() != 1 {
		panic("cannot PartialDecrypt: ct.Degree() != 1")
	}

	ringQ.NTTLazyLvl(level, ct.Value[1], share)

	ringQ.MulCoeffsMontgomeryLvl(level, share, dec.sk.Value.Q, share)

	ringQ.InvNTTLvl(level, share, share)

	// Add noise if specified
	if noise != nil {
		switch n := noise.(type) {
		case *ring.Poly:
			ringQ.AddLvl(level, share, n, share)
		case int:
			dec.addNoise(share, noise.(int))
		default:
			panic("cannot PartialDecrypt: invalid noise type")
		}
	}

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
