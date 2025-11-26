package protocol

import (
	"testing"

	"spdz-go/hpbfv"
	"spdz-go/rlwe"

	"crypto/rand"
	"math/big"
)

func TestSohoTripleGeneration(t *testing.T) {
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
	bs := make([]*hpbfv.Message, len(parties))

	cas := make([]*hpbfv.Ciphertext, len(parties))
	cbs := make([]*hpbfv.Ciphertext, len(parties))

	// Round 1 (Sampling Stage)
	for i, party := range parties {
		as[i], bs[i], cas[i], cbs[i] = party.BufferTriplesRoundOne()
	}

	// Round 2 (Multiplication Stage)
	ss := make([]*hpbfv.Message, len(parties))
	css := make([]*hpbfv.Ciphertext, len(parties))
	var cc *hpbfv.Ciphertext
	for i, party := range parties {
		cc, ss[i], css[i] = party.BufferTriplesRoundTwo(cas, cbs)
	}

	// Round 3 (Reshare Stage 1)
	var sumC *hpbfv.Ciphertext
	dshs := make([]*DistDecShare, len(parties))
	for i, party := range parties {
		sumC, dshs[i] = party.BufferTriplesRoundThree(cc, css)
	}

	for i, party := range parties {
		party.FinalizeTriple(as[i], bs[i], sumC, ss[i], dshs)
	}

	// Verify triples (Need to be summed up)

	for i := range parties[0].triples {
		aSum := big.NewInt(0)
		bSum := big.NewInt(0)
		cSum := big.NewInt(0)

		for _, party := range parties {
			triple := party.triples[i]
			aSum.Add(aSum, triple.A)
			bSum.Add(bSum, triple.B)
			cSum.Add(cSum, triple.C)
		}

		aSum.Mod(aSum, params.T())
		bSum.Mod(bSum, params.T())
		cSum.Mod(cSum, params.T())

		ab := new(big.Int).Mul(aSum, bSum)
		ab.Mod(ab, params.T())

		if cSum.Cmp(ab) != 0 {
			t.Fatalf("Triple check failed: A=%s, B=%s, C=%s, but A*B=%s", aSum.String(), bSum.String(), cSum.String(), ab.String())
		}
	}
}
