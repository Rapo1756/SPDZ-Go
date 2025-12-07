package hpbfv

import (
	/*
		  "encoding/json"
			"flag"
			"runtime"

			"github.com/stretchr/testify/require"
	*/

	"testing"

	"spdz-go/ring"
	"spdz-go/rlwe"
	"spdz-go/utils"

	"github.com/stretchr/testify/assert"
)

type mpTestContext struct {
	params   Parameters
	ringQ    *ring.Ring
	prng     utils.PRNG
	uSampler *ring.UniformSampler

	// For MP-GBFV
	numParties int
	crs        []byte
	kgens      []*PartialKeyGenerator
	psks       []*rlwe.SecretKey
	ppks       []*rlwe.PublicKey
	prlks      []*RelinearizationKey
	jsk        *rlwe.SecretKey
	jpk        *rlwe.PublicKey
	jrlk       *RelinearizationKey
	enc        *Encryptor
	ecd        *Encoder
	dcd        *Decoder
	meval      *MEvaluator
	ddecs      []*DistributedDecryptor
	jdec       *Decryptor
}

func genMPTestParams(params Parameters, numParties int) (testctx *mpTestContext, err error) {

	testctx = new(mpTestContext)
	testctx.params = params

	testctx.prng, err = utils.NewPRNG()
	if err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringQ)

	// For MP-GBFV
	testctx.numParties = numParties

	testctx.crs = make([]byte, 32)
	_, err = testctx.prng.Read(testctx.crs)
	if err != nil {
		return nil, err
	}

	testctx.kgens = make([]*PartialKeyGenerator, testctx.numParties)
	testctx.psks = make([]*rlwe.SecretKey, testctx.numParties)
	testctx.ppks = make([]*rlwe.PublicKey, testctx.numParties)
	testctx.prlks = make([]*RelinearizationKey, testctx.numParties)
	testctx.ddecs = make([]*DistributedDecryptor, testctx.numParties)
	for i := 0; i < testctx.numParties; i++ {
		testctx.kgens[i] = NewPartialKeyGenerator(testctx.params, testctx.crs)
		testctx.psks[i] = testctx.kgens[i].GenSecretKey()
		testctx.ppks[i], testctx.prlks[i] = testctx.kgens[i].GenPartialKeys(testctx.psks[i])
		testctx.ddecs[i] = NewDistributedDecryptor(testctx.params, testctx.psks[i])
	}
	testctx.jpk, testctx.jrlk = testctx.kgens[0].AggregateKeys(testctx.ppks, testctx.prlks)
	testctx.enc = NewEncryptor(testctx.params, testctx.jpk)
	testctx.ecd = NewEncoder(testctx.params)
	testctx.dcd = NewDecoder(testctx.params)
	testctx.meval = NewMEvaluator(testctx.params)

	// Generate the joint secret key for testing
	testctx.jsk = rlwe.NewSecretKey(params.Parameters)
	for i := 0; i < len(testctx.psks); i++ {
		params.RingQP().AddLvl(params.QCount()-1, params.PCount()-1, testctx.jsk.Value, testctx.psks[i].Value, testctx.jsk.Value)
	}
	testctx.jdec = NewDecryptor(testctx.params, testctx.jsk)

	return

}

func genMPTestVectors(testctx *mpTestContext) (msg *Message) {
	params := testctx.params
	coeffs := testctx.uSampler.ReadNew()
	msg = NewMessage(params)
	testctx.ringQ.PolyToBigint(coeffs, params.N()/params.Slots(), msg.Value)

	for i := 0; i < params.Slots(); i++ {
		msg.Value[i].Mod(msg.Value[i], params.T())
	}

	return
}

func TestMPGPFV(t *testing.T) {
	params := NewParametersFromLiteral(SOHO)
	crs := make([]byte, 32)
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatal(err)
	}
	prng.Read(crs)

	testctx, err := genMPTestParams(params, 100)
	if err != nil {
		t.Fatal(err)
	}

	testSetup(testctx, t)
	testDistDec(testctx, t)
	testEval(testctx, t)
}

func testSetup(testctx *mpTestContext, t *testing.T) {
	params := testctx.params
	ringQP := params.RingQP()

	t.Run(testString("PartialKeyGen", params), func(t *testing.T) {
		for i := 0; i < len(testctx.ppks); i++ {
			for j := 0; j < len(testctx.ppks); j++ {
				if i == j {
					continue
				}
				assert.NotEqual(t, testctx.ppks[i].Value[0], testctx.ppks[j].Value[0], "PublicKey ct.Value[0] are equal")
				assert.Equal(t, testctx.ppks[i].Value[1], testctx.ppks[j].Value[1], "PublicKey ct.Value[1] are not equal")
			}
		}
		prlks := testctx.prlks
		for i := 0; i < len(prlks); i++ {
			for j := 0; j < len(prlks[0].V.Value); j++ {
				for k := 0; k < len(prlks[0].V.Value[0]); k++ {
					assert.Equal(t, prlks[i].V.Value[j][k].Value[1], testctx.kgens[i].U[j][k], "RelinearizationKey V[%d][%d] Value[1] is not equal to keygen.U[%d][%d]", j, k, j, k)
				}
			}
		}
	})

	t.Run(testString("AggregateKeys", params), func(t *testing.T) {
		// Generate key from the sum of secret keys
		keygen_t := NewPartialKeyGenerator(params, testctx.crs)
		pk_t, _ := keygen_t.GenPartialKeys(testctx.jsk)

		assert.Equal(t, testctx.jpk.Value[1], pk_t.Value[1], "Joint PublicKey does not match the PublicKey generated from the sum of secret keys")
		// Check noise of jpk.Value[0]
		diff := ringQP.NewPoly()
		ringQP.SubLvl(params.QCount()-1, params.PCount()-1, testctx.jpk.Value[0], pk_t.Value[0], diff)
		ringQP.InvMFormLvl(params.QCount()-1, params.PCount()-1, diff, diff)
		ringQP.InvNTTLvl(params.QCount()-1, params.PCount()-1, diff, diff)
		// 6 * sigma * number_of_parties
		bound := uint64(6 * params.Sigma() * float64(len(testctx.psks)))
		coeffs := diff.Q.Coeffs[0]
		q0 := params.Q()[0]
		for i, c := range coeffs {
			if c > bound && c < (q0-bound) {
				t.Fatalf("Aggregation check failed at coefficient %d. Value: %d. (Expected noise < %d)", i, c, bound)
			}
		}
	})

	t.Run(testString("JointKey", params), func(t *testing.T) {
		dec := NewDecryptor(params, testctx.jsk)
		msg := genMPTestVectors(testctx)
		ct := testctx.enc.EncryptMsgNew(msg)
		msgOut := dec.DecryptToMsgNew(ct)
		for i := 0; i < params.Slots(); i++ {
			assert.Equal(t, 0, msgOut.Value[i].Cmp(msg.Value[i]), "Joint key Encryption/Decryption test failed at index %d: got %s, want %s", i, msgOut.Value[i].Text(10), msg.Value[i].Text(10))
		}
	})
}

func testDistDec(testctx *mpTestContext, t *testing.T) {
	params := testctx.params

	msg := genMPTestVectors(testctx)

	ct := testctx.enc.EncryptMsgNew(msg)

	shares := make([]*DistDecShare, testctx.numParties)
	for i := 0; i < testctx.numParties; i++ {
		shares[i] = testctx.ddecs[i].PartialDecrypt(ct, 80)
	}

	msgOutD := testctx.ddecs[0].JointDecryptToMsgNew(ct, shares)

	t.Run(testString("DistributedDecryption", params), func(t *testing.T) {
		for i := 0; i < params.Slots(); i++ {
			if msgOutD.Value[i].Cmp(msg.Value[i]) != 0 {
				t.Fatalf("Distributed Decryption test failed at index %d: got %s, want %s", i, msgOutD.Value[i].Text(10), msg.Value[i].Text(10))
			}
		}
	})
}

func testEval(testctx *mpTestContext, t *testing.T) {
	params := testctx.params
	msg1 := genMPTestVectors(testctx)
	msg2 := genMPTestVectors(testctx)

	ct1 := testctx.enc.EncryptMsgNew(msg1)
	ct2 := testctx.enc.EncryptMsgNew(msg2)

	pt := testctx.ecd.EncodeNew(msg2)

	msgAdd := NewMessage(params)
	for i := 0; i < params.Slots(); i++ {
		msgAdd.Value[i].Add(msg1.Value[i], msg2.Value[i])
		msgAdd.Value[i].Mod(msgAdd.Value[i], params.T())
	}
	msgMul := NewMessage(params)
	for i := 0; i < params.Slots(); i++ {
		msgMul.Value[i].Mul(msg1.Value[i], msg2.Value[i])
		msgMul.Value[i].Mod(msgMul.Value[i], params.T())
	}

	t.Run(testString("Add", params), func(t *testing.T) {
		ctAdd := testctx.meval.AddNew(ct1, ct2)
		msgOutD := testctx.jdec.DecryptToMsgNew(ctAdd)

		for i := 0; i < params.Slots(); i++ {
			if msgOutD.Value[i].Cmp(msgAdd.Value[i]) != 0 {
				t.Fatalf("Add test failed at index %d: got %s, want %s", i, msgOutD.Value[i].Text(10), msgAdd.Value[i].Text(10))
			}
		}
	})

	t.Run(testString("PlaintextAdd", params), func(t *testing.T) {
		ctAdd := testctx.meval.PlaintextAddNew(ct1, pt)
		msgOutD := testctx.jdec.DecryptToMsgNew(ctAdd)

		for i := 0; i < params.Slots(); i++ {
			if msgOutD.Value[i].Cmp(msgAdd.Value[i]) != 0 {
				t.Fatalf("PlaintextAdd test failed at index %d: got %s, want %s", i, msgOutD.Value[i].Text(10), msgAdd.Value[i].Text(10))
			}
		}
	})

	t.Run(testString("PlaintextMul", params), func(t *testing.T) {
		ctMul := testctx.meval.PlaintextMulNew(ct1, pt)
		msgOutD := testctx.jdec.DecryptToMsgNew(ctMul)

		for i := 0; i < params.Slots(); i++ {
			if msgOutD.Value[i].Cmp(msgMul.Value[i]) != 0 {
				t.Fatalf("PlaintextMul test failed at index %d: got %s, want %s", i, msgOutD.Value[i].Text(10), msgMul.Value[i].Text(10))
			}
		}
	})

	t.Run(testString("MulRelin", params), func(t *testing.T) {
		ctMulRelin := testctx.meval.MulAndRelinNew(ct1, ct2, testctx.jrlk)
		msgOutD := testctx.jdec.DecryptToMsgNew(ctMulRelin)

		for i := 0; i < params.Slots(); i++ {
			if msgOutD.Value[i].Cmp(msgMul.Value[i]) != 0 {
				t.Fatalf("MulRelin test failed at index %d: got %s, want %s", i, msgOutD.Value[i].Text(10), msgMul.Value[i].Text(10))
			}
		}
	})
}
