package protocol

import (
	"testing"

	"spdz-go/hpbfv"
	"spdz-go/rlwe"

	"math/big"
)

func TestHemiPrep(t *testing.T) {
	// Generate two ciphertexts and test distributed decryption shares
	params := hpbfv.NewParametersFromLiteral(hpbfv.HPN13D10T128)

	parties := make([]*HemiParty, 3)
	for i := 0; i < len(parties); i++ {
		parties[i] = NewHemiParty(i, params, len(parties))
	}
	pks := make([][]*rlwe.PublicKey, len(parties))

	// Round 0: Key Generation
	for i, party := range parties {
		pks[i] = party.InitSetup(len(parties)) // temp = pk_{i, _}
	}

	for i, party := range parties {
		pksTemp := make([]*rlwe.PublicKey, len(parties))
		for j := 0; j < len(parties); j++ {
			pksTemp[j] = pks[j][i] // pk_{_, i}
		}
		party.FinalizeSetup(pksTemp)
	}

	// Round 1: Sample and exchange triples
	as := make([]*hpbfv.Message, len(parties))
	bs := make([]*hpbfv.Message, len(parties))
	for i, party := range parties {
		as[i], bs[i] = party.SampleAandB()
	}

	cAs := make([][]*hpbfv.Ciphertext, len(parties))

	// Pairwise Round 1: Pairwise exchange and compute triples
	for i, party := range parties {
		cAs[i] = make([]*hpbfv.Ciphertext, len(parties))
		for j := range parties {
			if i == j {
				continue
			}
			cAs[i][j] = party.PairewiseRoundOne(as[i], j) // Send to party j
		}
	}

	ejis := make([][]*hpbfv.Message, len(parties))
	cijs := make([][]*hpbfv.Ciphertext, len(parties))
	for j := range parties {
		ejis[j] = make([]*hpbfv.Message, len(parties))
	}
	// Pairwise Round 2: Pairwise finalize triples
	for i := range parties {
		cijs[i] = make([]*hpbfv.Ciphertext, len(parties))
		for j, party := range parties {
			if i == j {
				continue
			}
			ejis[j][i], cijs[i][j] = party.PairewiseRoundTwo(cAs[i][j], bs[j], i)
		}
	}

	// Finalize triples
	for i, party := range parties {
		party.Finalize(as[i], bs[i], ejis[i], cijs[i])
	}

	// Check triples
	for i := range parties[0].triples {
		// Sum up triples from all parties
		aSum := new(big.Int)
		bSum := new(big.Int)
		cSum := new(big.Int)
		for _, party := range parties {
			aSum.Add(aSum, party.triples[i].A)
			bSum.Add(bSum, party.triples[i].B)
			cSum.Add(cSum, party.triples[i].C)
		}
		aSum.Mod(aSum, params.T())
		bSum.Mod(bSum, params.T())
		cSum.Mod(cSum, params.T())

		// Check if cSum = aSum * bSum
		ab := new(big.Int).Mul(aSum, bSum)
		ab.Mod(ab, params.T())

		if cSum.Cmp(ab) != 0 {
			t.Fatalf("Triple check failed at index %d: a=%s, b=%s, c=%s, ab=%s", i, aSum.String(), bSum.String(), cSum.String(), ab.String())
		}
	}
}
