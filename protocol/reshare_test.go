package protocol

import (
	"testing"

	"spdz-go/hpbfv"
	"spdz-go/ring"
	"spdz-go/rlwe"

	"crypto/rand"
	"math/big"
)

func TestReshare(t *testing.T) {
	// Generate two ciphertexts and test distributed decryption shares
	params := hpbfv.NewParametersFromLiteral(hpbfv.HPN13D10T128)

	crs := make([]byte, 32)
	_, err := rand.Read(crs)
	if err != nil {
		t.Fatalf("cannot generate crs: %v", err)
	}

	p1 := NewSohoParty(0, params, crs)
	p2 := NewSohoParty(1, params, crs)
	p3 := NewSohoParty(2, params, crs)

	parties := []*SohoParty{p1, p2, p3}

	ppks := make([]*rlwe.PublicKey, len(parties))
	prlks := make([]*hpbfv.RelinearizationKey, len(parties))

	for i, party := range parties {
		ppks[i] = party.ppk
		prlks[i] = party.prlk
	}

	for _, party := range parties {
		party.Setup(ppks, prlks)
	}

	a1, ca1 := p1.SampleUniformModTAndEncrypt()
	a2, ca2 := p2.SampleUniformModTAndEncrypt()
	a3, ca3 := p3.SampleUniformModTAndEncrypt()

	// Sum of a1, a2, a3
	aSum := make([]*big.Int, params.Slots())
	for i := 0; i < params.Slots(); i++ {
		aSum[i] = new(big.Int).Add(a1.Value[i], a2.Value[i])
		aSum[i].Add(aSum[i], a3.Value[i])
		aSum[i].Mod(aSum[i], params.T())
	}

	b1, cb1 := p1.SampleUniformModTAndEncrypt()
	b2, cb2 := p2.SampleUniformModTAndEncrypt()
	b3, cb3 := p3.SampleUniformModTAndEncrypt()

	// Sum of b1, b2, b3
	bSum := make([]*big.Int, params.Slots())
	for i := 0; i < params.Slots(); i++ {
		bSum[i] = new(big.Int).Add(b1.Value[i], b2.Value[i])
		bSum[i].Add(bSum[i], b3.Value[i])
		bSum[i].Mod(bSum[i], params.T())
	}

	ca := p1.eval.AddNew(ca1, ca2)
	ca = p1.eval.AddNew(ca, ca3)

	// Check if ca is encryption of aSum
	dca1 := p1.ddec.PartialDecrypt(ca)
	dca2 := p2.ddec.PartialDecrypt(ca)
	dca3 := p3.ddec.PartialDecrypt(ca)

	decMsg := p1.ddec.JointDecryptToMsgNew(ca, []*ring.Poly{dca1, dca2, dca3})

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(aSum[i]) != 0 {
			t.Fatalf("aSum = %s, but decrypted aSum = %s", aSum[i].String(), decMsg.Value[i].String())
		}
	}

	cb := p1.eval.AddNew(cb1, cb2)
	cb = p1.eval.AddNew(cb, cb3)

	// Check if cb is encryption of bSum
	dcb1 := p1.ddec.PartialDecrypt(cb)
	dcb2 := p2.ddec.PartialDecrypt(cb)
	dcb3 := p3.ddec.PartialDecrypt(cb)

	decMsg = p1.ddec.JointDecryptToMsgNew(cb, []*ring.Poly{dcb1, dcb2, dcb3})

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(bSum[i]) != 0 {
			t.Fatalf("bSum = %s, but decrypted bSum = %s", bSum[i].String(), decMsg.Value[i].String())
		}
	}

	cc := p1.eval.MulAndRelinNew(ca, cb, p1.jrlk)

	// Check if cc is encryption of aSum * bSum
	dcc1 := p1.ddec.PartialDecrypt(cc)
	dcc2 := p2.ddec.PartialDecrypt(cc)
	dcc3 := p3.ddec.PartialDecrypt(cc)

	decMsg = p1.ddec.JointDecryptToMsgNew(cc, []*ring.Poly{dcc1, dcc2, dcc3})

	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Mod(expected, params.T())
		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("c = aSum * bSum = %s, but decrypted c = %s", expected.String(), decMsg.Value[i].String())
		}
	}

	s1, cs1 := p1.SampleUniformModTAndEncrypt()
	s2, cs2 := p2.SampleUniformModTAndEncrypt()
	s3, cs3 := p3.SampleUniformModTAndEncrypt()

	sum := p1.AggregateAndAdd(cc, []*hpbfv.Ciphertext{cs1, cs2, cs3})

	dsh1 := p1.ddec.PartialDecrypt(sum)
	dsh2 := p2.ddec.PartialDecrypt(sum)
	dsh3 := p3.ddec.PartialDecrypt(sum)

	decMsg = p1.ddec.JointDecryptToMsgNew(sum, []*ring.Poly{dsh1, dsh2, dsh3})

	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Add(s1.Value[i], s2.Value[i])
		expected.Add(expected, s3.Value[i])
		tmp := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Add(expected, tmp)
		expected.Mod(expected, params.T())

		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("sSum + c = %s, but decrypted sSum + c = %s", expected.String(), decMsg.Value[i].String())
		}
	}

	// decMsg - s1 - s2 - s3 should be equal to c
	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Mod(expected, params.T())

		decMsg.Value[i].Sub(decMsg.Value[i], s1.Value[i])
		decMsg.Value[i].Sub(decMsg.Value[i], s2.Value[i])
		decMsg.Value[i].Sub(decMsg.Value[i], s3.Value[i])
		decMsg.Value[i].Mod(decMsg.Value[i], params.T())

		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("After subtracting shares, value = %s, but expected = %s", decMsg.Value[i].String(), expected.String())
		}
	}

	res1 := p1.Reshare(sum, []*DistDecShare{&DistDecShare{dsh1}, &DistDecShare{dsh2}, &DistDecShare{dsh3}}, s1)
	res2 := p2.Reshare(sum, []*DistDecShare{&DistDecShare{dsh1}, &DistDecShare{dsh2}, &DistDecShare{dsh3}}, s2)
	res3 := p3.Reshare(sum, []*DistDecShare{&DistDecShare{dsh1}, &DistDecShare{dsh2}, &DistDecShare{dsh3}}, s3)

	finalMsg := hpbfv.NewMessage(params)
	for i := 0; i < params.Slots(); i++ {
		finalMsg.Value[i] = new(big.Int).Add(res1.Value[i], res2.Value[i])
		finalMsg.Value[i].Add(finalMsg.Value[i], res3.Value[i])
		finalMsg.Value[i].Mod(finalMsg.Value[i], params.T())
	}

	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Mod(expected, params.T())

		if finalMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("Reshared message[%d] = %s, but expected = %s", i, finalMsg.Value[i].String(), expected.String())
		}
	}
}
