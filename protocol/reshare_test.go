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


	parties := make([]*SohoParty, 3)

	for i := 0; i < len(parties); i++ {
		parties[i] = NewSohoParty(i, params, crs)
	}

	// Round 0 (Key Generation)
	ppks := make([]*rlwe.PublicKey, len(parties))
	prlks := make([]*hpbfv.RelinearizationKey, len(parties))

	for i, party := range parties {
		ppks[i] = party.ppk
		prlks[i] = party.prlk
	}

	for _, party := range parties {
		party.Setup(ppks, prlks)
	}

	as := make([]*hpbfv.Message, len(parties))
	cas := make([]*hpbfv.Ciphertext, len(parties))

	bs := make([]*hpbfv.Message, len(parties))
	cbs := make([]*hpbfv.Ciphertext, len(parties))

	// Round 1 (Sampling Stage)
	for i, party := range parties {
		as[i], cas[i] = party.SampleUniformModTAndEncrypt()
		bs[i], cbs[i] = party.SampleUniformModTAndEncrypt()
	}

	aSum := make([]*big.Int, params.Slots())
	bSum := make([]*big.Int, params.Slots())

	for i := 0; i < params.Slots(); i++ {
		aSum[i] = big.NewInt(0)
		bSum[i] = big.NewInt(0)
		for j := 0; j < len(parties); j++ {
			aSum[i].Add(aSum[i], as[j].Value[i])
			bSum[i].Add(bSum[i], bs[j].Value[i])
		}
		aSum[i].Mod(aSum[i], params.T())
		bSum[i].Mod(bSum[i], params.T())
	}

	ca := parties[0].Aggregate(cas)
	cb := parties[0].Aggregate(cbs)

	// Check if ca is encryption of aSum
	dcas := make([]*ring.Poly, len(parties))
	for i, party := range parties {
		dcas[i] = party.ddec.PartialDecrypt(ca, 80)
	}

	decMsg := parties[0].ddec.JointDecryptToMsgNew(ca, dcas)

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(aSum[i]) != 0 {
			t.Fatalf("aSum = %s, but decrypted aSum = %s", aSum[i].String(), decMsg.Value[i].String())
		}
	}

	// Check if cb is encryption of bSum
	dcbs := make([]*ring.Poly, len(parties))
	for i, party := range parties {
		dcbs[i] = party.ddec.PartialDecrypt(cb, 80)
	}
	decMsg = parties[0].ddec.JointDecryptToMsgNew(cb, dcbs)

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(bSum[i]) != 0 {
			t.Fatalf("bSum = %s, but decrypted bSum = %s", bSum[i].String(), decMsg.Value[i].String())
		}
	}

	cc := parties[0].eval.MulAndRelinNew(ca, cb, parties[0].jrlk)

	// Check if cc is encryption of aSum * bSum
	dccs := make([]*ring.Poly, len(parties))
	for i, party := range parties {
		dccs[i] = party.ddec.PartialDecrypt(cc, 80)
	}
	decMsg = parties[0].ddec.JointDecryptToMsgNew(cc, dccs)

	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Mod(expected, params.T())
		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("c = aSum * bSum = %s, but decrypted c = %s", expected.String(), decMsg.Value[i].String())
		}
	}
	ss := make([]*hpbfv.Message, len(parties))
	css := make([]*hpbfv.Ciphertext, len(parties))

	// Each party samples share of noise
	for i, party := range parties {
		ss[i], css[i] = party.SampleUniformModTAndEncrypt()
	}

	// Compute sSum + c
	sum := parties[0].AggregateAndAdd(cc, css)

	dshs := make([]*ring.Poly, len(parties))
	for i, party := range parties {
		dshs[i] = party.ddec.PartialDecrypt(sum, 80)
	}
	decMsg = parties[0].ddec.JointDecryptToMsgNew(sum, dshs)

	for i := 0; i < params.Slots(); i++ {
		expected := big.NewInt(0)
		for j := 0; j < len(parties); j++ {
			expected.Add(expected, ss[j].Value[i])
		}
		tmp := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Add(expected, tmp)
		expected.Mod(expected, params.T())

		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("sSum + c = %s, but decrypted sSum + c = %s", expected.String(), decMsg.Value[i].String())
		}
	}

	// decMsg
	for i := 0; i < params.Slots(); i++ {
		expected := new(big.Int).Mul(aSum[i], bSum[i])
		expected.Mod(expected, params.T())
		for j := 0; j < len(parties); j++ {
			decMsg.Value[i].Sub(decMsg.Value[i], ss[j].Value[i])
		}
		decMsg.Value[i].Mod(decMsg.Value[i], params.T())

		if decMsg.Value[i].Cmp(expected) != 0 {
			t.Fatalf("After subtracting shares, value = %s, but expected = %s", decMsg.Value[i].String(), expected.String())
		}
	}
	ress := make([]*hpbfv.Message, len(parties))
	dsh2s := make([]*DistDecShare, len(parties))
	// Each party computes reshare shares
	for i, _ := range parties {
		dsh2s[i] = &DistDecShare{dshs[i]}
	}
	// Each party resharing
	for i, party := range parties {
		ress[i] = party.Reshare(sum, dsh2s, ss[i])
	}

	finalMsg := hpbfv.NewMessage(params)
	for i := 0; i < params.Slots(); i++ {
		finalMsg.Value[i] = big.NewInt(0)
		for j := 0; j < len(parties); j++ {
			finalMsg.Value[i].Add(finalMsg.Value[i], ress[j].Value[i])
		}
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
