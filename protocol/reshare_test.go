package protocol

import (
	"testing"

	"spdz-go/hpbfv"
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
		as[i] = party.SampleUniformModT()
		cas[i] = party.enc.EncryptMsgNew(as[i])

		bs[i] = party.SampleUniformModT()
		cbs[i] = party.enc.EncryptMsgNew(bs[i])
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

	cc := parties[0].eval.MulAndRelinNew(ca, cb, parties[0].jrlk)

	// Check if ca, cb, cc is encryption of aSum, bSum, aSum*bSum
	dcas := make([]*hpbfv.DistDecShare, len(parties))
	dcbs := make([]*hpbfv.DistDecShare, len(parties))
	dccs := make([]*hpbfv.DistDecShare, len(parties))
	for i, party := range parties {
		dcas[i] = party.ddec.PartialDecrypt(ca, 80)
		dcbs[i] = party.ddec.PartialDecrypt(cb, 80)
		dccs[i] = party.ddec.PartialDecrypt(cc, 80)
	}

	decMsg := parties[0].ddec.JointDecryptToMsgNew(ca, dcas)

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(aSum[i]) != 0 {
			t.Fatalf("aSum = %s, but decrypted aSum = %s", aSum[i].String(), decMsg.Value[i].String())
		}
	}
	decMsg = parties[0].ddec.JointDecryptToMsgNew(cb, dcbs)

	for i := 0; i < params.Slots(); i++ {
		if decMsg.Value[i].Cmp(bSum[i]) != 0 {
			t.Fatalf("bSum = %s, but decrypted bSum = %s", bSum[i].String(), decMsg.Value[i].String())
		}
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
	dshs := make([]*hpbfv.DistDecShare, len(parties))

	// Each party samples share of noise
	for i, party := range parties {
		ss[i], dshs[i] = party.ReshareInit(cc, 80)
	}
	
	ress := make([]*hpbfv.Message, len(parties))
	// Each party resharing
	for i, party := range parties {
		ress[i] = party.ReshareFinalize(cc, dshs, ss[i])
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
