package protocol

import (
	"testing"

	"spdz-go/hpbfv"
	"spdz-go/rlwe"

	"math/big"
	"sync"
)

// Messages for channel communication
type hemiPkMsg struct {
	SenderID int
	Key      *rlwe.PublicKey
}

type hemiRoundOneMessage struct {
	SenderID   int
	Ciphertext *hpbfv.Ciphertext
}

type hemiRoundTwoMessage struct {
	SenderID   int
	Ciphertext *hpbfv.Ciphertext
}

// hemiPartyChannels holds the input channels for a specific party
type hemiPartyChannels struct {
	pkIn chan hemiPkMsg
	r1In chan hemiRoundOneMessage
	r2In chan hemiRoundTwoMessage
}

func TestHemiPrep(t *testing.T) {
	params := hpbfv.NewParametersFromLiteral(hpbfv.HEMI)

	// Number of Parties
	numParties := 3

	// Initialize Channels
	partyChans := make([]hemiPartyChannels, numParties)
	for i := 0; i < numParties; i++ {
		partyChans[i] = hemiPartyChannels{
			pkIn: make(chan hemiPkMsg, numParties),
			r1In: make(chan hemiRoundOneMessage, numParties),
			r2In: make(chan hemiRoundTwoMessage, numParties),
		}
	}

	finishedParties := make(chan *HemiParty, numParties)
	var wg sync.WaitGroup

	// Start Parties
	for i := 0; i < numParties; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			runParty(pid, numParties, params, partyChans, finishedParties)
		}(i)
	}
	wg.Wait()
	close(finishedParties)

	parties := make([]*HemiParty, numParties)
	for p := range finishedParties {
		parties[p.id] = p
	}

	for i := range parties[0].triples {
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
			t.Errorf("Triple check failed at index %d: a=%s, b=%s, c=%s, ab=%s", i, aSum.String(), bSum.String(), cSum.String(), ab.String())
		}
	}
}

// runParty executes the protocol logic for a single party
func runParty(id, numParties int, params hpbfv.Parameters, allChans []hemiPartyChannels, resultChan chan<- *HemiParty) {
	party := NewHemiParty(id, params, numParties)

	//  --- Round 0: Key Generation & Exchange ---
	pk := party.InitSetup(numParties)
	for peer := 0; peer < numParties; peer++ {
		// Send own public keys to all other parties
		allChans[peer].pkIn <- hemiPkMsg{SenderID: id, Key: pk[peer]}
	}
	// Collect public keys from everyone
	pks := make([]*rlwe.PublicKey, numParties)
	for j := 0; j < numParties; j++ {
		msg := <-allChans[id].pkIn
		pks[msg.SenderID] = msg.Key
	}
	party.FinalizeSetup(pks)

	// Sample a and b
	a, b := party.SampleAandB()

	// --- Round 1 (Pairwise): Encrypt a with peer's public key ---
	for peer := 0; peer < numParties; peer++ {
		if peer == id {
			continue
		}
		cA := party.PairwiseRoundOne(a, peer)

		// Send a's encryption by peer's public key to peer
		allChans[peer].r1In <- hemiRoundOneMessage{SenderID: id, Ciphertext: cA}
	}

	// Receive cA from other parties
	cAs := make([]*hpbfv.Ciphertext, numParties)
	for i := 0; i < numParties - 1; i++ {
		msg := <-allChans[id].r1In
		cAs[msg.SenderID] = msg.Ciphertext
	}

	// --- Round 2 (Pairwise): compute e_{i,j} and c_{i,j} ---
	ejis := make([]*hpbfv.Message, numParties)
	for peer := 0; peer < numParties; peer++ {
		if peer == id {
			continue
		}
		// Compute e_{i,j} and c_{i,j}
		var cij *hpbfv.Ciphertext
		ejis[peer], cij = party.PairwiseRoundTwo(cAs[peer], b, peer)

		// Send cij to peer
		allChans[peer].r2In <- hemiRoundTwoMessage{SenderID: id, Ciphertext: cij}
	}
	// Receive cij from other parties
	cijs := make([]*hpbfv.Ciphertext, numParties)
	for i := 0; i < numParties - 1; i++ {
		msg := <-allChans[id].r2In
		cijs[msg.SenderID] = msg.Ciphertext
	}

	// --- Finalize ---
	party.Finalize(a, b, ejis, cijs)
	resultChan <- party
}
