package protocol

import (
	"testing"

	"spdz-go/hpbfv"
	"spdz-go/rlwe"

	"crypto/rand"
	"math/big"

	"sync"
)

// --- Message Structs for Phases ---

// Round 0: Public Keys and Relinearization Keys
type sohoKeyMsg struct {
	senderID int
	ppk      *rlwe.PublicKey
	prlk     *hpbfv.RelinearizationKey
}

// Round 1: Ciphertexts (CA, CB)
type sohoCTMsg struct {
	senderID int
	cA       *hpbfv.Ciphertext
	cB       *hpbfv.Ciphertext
}

// Round 2: Distributed Decryption Shares
type sohoShareMsg struct {
	senderID int
	ddsh     *hpbfv.DistDecShare
}

// Channels for a single party
type sohoPartyChannels struct {
	keyIn   chan sohoKeyMsg
	ctIn    chan sohoCTMsg
	shareIn chan sohoShareMsg
}

func TestSohoPrep(t *testing.T) {
	// Common Setup
	params := hpbfv.NewParametersFromLiteral(hpbfv.SOHO)
	crs := make([]byte, 32)
	if _, err := rand.Read(crs); err != nil {
		t.Fatalf("cannot generate crs: %v", err)
	}

	// Number of Parties
	numParties := 3

	// Initialize Channels
	partyChans := make([]sohoPartyChannels, numParties)
	for i := 0; i < numParties; i++ {
		partyChans[i] = sohoPartyChannels{
			keyIn:   make(chan sohoKeyMsg, numParties),
			ctIn:    make(chan sohoCTMsg, numParties),
			shareIn: make(chan sohoShareMsg, numParties),
		}
	}

	// Channel to collect finished parties
	finishedParties := make(chan *SohoParty, numParties)
	var wg sync.WaitGroup

	// Start Parties
	for i := 0; i < numParties; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			runSohoParty(pid, numParties, params, crs, partyChans, finishedParties)
		}(i)
	}
	wg.Wait()
	close(finishedParties)

	parties := make([]*SohoParty, numParties)
	for p := range finishedParties {
		parties[p.id] = p
	}

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
			t.Fatalf("Triple check failed at index %d: A=%s, B=%s, C=%s, but A*B=%s", i, aSum.String(), bSum.String(), cSum.String(), ab.String())
		}
	}
}

func runSohoParty(id, numParties int, params hpbfv.Parameters, crs []byte, allChans []sohoPartyChannels, resultChan chan<- *SohoParty) {
	// --- Round 0: Key Generation & Exchange ---
	party := NewSohoParty(id, params, crs)
	myKeyMsg := sohoKeyMsg{
		senderID: id,
		ppk:      party.ppk,
		prlk:     party.prlk,
	}
	for peer := 0; peer < numParties; peer++ {
		allChans[peer].keyIn <- myKeyMsg
	}
	ppks := make([]*rlwe.PublicKey, numParties)
	prlks := make([]*hpbfv.RelinearizationKey, numParties)
	for i := 0; i < numParties; i++ {
		msg := <-allChans[id].keyIn
		ppks[msg.senderID] = msg.ppk
		prlks[msg.senderID] = msg.prlk
	}
	party.Setup(ppks, prlks)

	// --- Round 1: Sampling & Exchange ---
	a, b, ca, cb := party.BufferTriplesRoundOne()

	// Broadcast my ciphertexts
	myCTMsg := sohoCTMsg{
		senderID: id,
		cA:       ca,
		cB:       cb,
	}
	for peer := 0; peer < numParties; peer++ {
		allChans[peer].ctIn <- myCTMsg
	}

	// Collect ciphertexts from everyone
	cas := make([]*hpbfv.Ciphertext, numParties)
	cbs := make([]*hpbfv.Ciphertext, numParties)
	for i := 0; i < numParties; i++ {
		msg := <-allChans[id].ctIn
		cas[msg.senderID] = msg.cA
		cbs[msg.senderID] = msg.cB
	}

	// --- Round 2: Multiplication & Resharing ---
	s, cc, dsh := party.BufferTriplesRoundTwo(cas, cbs, 80)

	// Broadcast my decryption share
	myShareMsg := sohoShareMsg{
		senderID: id,
		ddsh:     dsh,
	}
	for peer := 0; peer < numParties; peer++ {
		allChans[peer].shareIn <- myShareMsg
	}

	// Collect decryption shares from everyone
	dshs := make([]*hpbfv.DistDecShare, numParties)
	for i := 0; i < numParties; i++ {
		msg := <-allChans[id].shareIn
		dshs[msg.senderID] = msg.ddsh
	}

	// --- Finalize ---
	party.FinalizeTriple(a, b, cc, s, dshs)

	resultChan <- party
}
