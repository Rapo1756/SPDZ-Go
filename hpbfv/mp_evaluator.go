package hpbfv

import (
	"fmt"

	"spdz-go/ring"
	"spdz-go/rlwe"
	"spdz-go/rlwe/ringqp"
	"spdz-go/utils"
)

type MEvaluator struct {
	Evaluator
}

func NewMEvaluator(params Parameters) *MEvaluator {
	eval := new(Evaluator)
	eval.params = params
	eval.ksw = rlwe.NewEvaluator(params.Parameters, nil)
	eval.conv = ring.NewBasisExtender(params.RingQ(), params.RingQMul())

	for i := 0; i < len(eval.poolQ); i++ {
		eval.poolQ[i] = params.RingQ().NewPoly()
		eval.poolQMul[i] = params.RingQMul().NewPoly()
	}

	eval.poolKeySwitch = rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel())
	eval.poolCtMul = NewCiphertext(params, 2)

	return &MEvaluator{
		Evaluator: *eval,
	}
}

// getElemAndCheckBinary unwraps the elements from the operands and checks that the receiver has sufficiently large degree.
func (eval *MEvaluator) getElemAndCheckBinary(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext, opOutMinDegree int) (el0, el1, elOut *rlwe.Ciphertext) {
	if op0 == nil || op1 == nil || opOut == nil {
		panic("operands cannot be nil")
	}

	if op0.Degree()+op1.Degree() == 0 {
		panic("operands cannot be both plaintexts")
	}

	if opOut.Degree() < opOutMinDegree {
		panic("receiver operand degree is too small")
	}

	return op0.El(), op1.El(), opOut.El()
}

// evaluateInPlaceBinary applies the provided function in place on el0 and el1 and returns the result in elOut.
func (eval *MEvaluator) evaluateInPlaceBinary(el0, el1, elOut *rlwe.Ciphertext, evaluate func(*ring.Poly, *ring.Poly, *ring.Poly)) {

	smallest, largest, _ := rlwe.GetSmallestLargest(el0, el1)

	for i := 0; i < smallest.Degree()+1; i++ {
		evaluate(el0.Value[i], el1.Value[i], elOut.Value[i])
	}

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	if largest != nil && largest != elOut { // checks to avoid unnecessary work.
		for i := smallest.Degree() + 1; i < largest.Degree()+1; i++ {
			elOut.Value[i].Copy(largest.Value[i])
		}
	}
}

// relinearize is a method common to Relinearize and RelinearizeNew. It switches ct0 to the NTT domain, applies the keyswitch, and returns the result out of the NTT domain.
func (eval *MEvaluator) relinearize(ct0 *Ciphertext, rlk *RelinearizationKey, ctOut *Ciphertext) {

	if ctOut != ct0 {
		ring.Copy(ct0.Value[0], ctOut.Value[0])
		ring.Copy(ct0.Value[1], ctOut.Value[1])
	}

	ringQ := eval.params.RingQ()

	// c11 \bosdot BD = (c11 \boxdot b, c11 \boxdot d)
	eval.ksw.GadgetProduct(ct0.Value[2].Level(), ct0.Value[2], rlk.BD, eval.poolKeySwitch)

	// Add c11 \boxdot d to ctOut.Value[1]
	ringQ.Add(eval.poolKeySwitch.Value[1], ctOut.Value[1], ctOut.Value[1])

	// buffer for storing (c11 \ boxdot b)
	ring.CopyLvl(eval.poolKeySwitch.Value[0].Level(), eval.poolKeySwitch.Value[0], eval.poolQ[0])

	// (c11 \ boxdot B) \boxdot V = (c11 \boxdot b) \boxdot V, (c11 \boxdot b) \boxdot U)
	eval.ksw.GadgetProduct(eval.poolQ[0].Level(), eval.poolQ[0], rlk.V, eval.poolKeySwitch)
	// Add (c11 \ boxdot B) \boxdot V to ctOut
	ringQ.Add(eval.poolKeySwitch.Value[0], ctOut.Value[0], ctOut.Value[0])
	ringQ.Add(eval.poolKeySwitch.Value[1], ctOut.Value[1], ctOut.Value[1])

	ctOut.Resize(1, ctOut.Level())
}

// permute performs a column rotation on ct0 and returns the result in ctOut
func (eval *MEvaluator) permute(ct0 *Ciphertext, generator uint64, switchKey *rlwe.SwitchingKey, ctOut *Ciphertext) {
	ringQ := eval.params.RingQ()

	eval.ksw.GadgetProduct(ct0.Value[1].Level(), ct0.Value[1], switchKey.GadgetCiphertext, eval.poolKeySwitch)

	ringQ.Add(eval.poolKeySwitch.Value[0], ct0.Value[0], eval.poolKeySwitch.Value[0])

	ringQ.Permute(eval.poolKeySwitch.Value[0], generator, ctOut.Value[0])
	ringQ.Permute(eval.poolKeySwitch.Value[1], generator, ctOut.Value[1])
}

// RescaleQMul extends ct0 to the (Q, QMul) ring for hoisted multiplication.
func (eval *MEvaluator) RescaleQMul(ct0 *Ciphertext, ctOut []ringqp.Poly) {
	ringQ := eval.params.RingQ()
	ringQMul := eval.params.RingQMul()
	levelQ := len(ringQ.Modulus) - 1
	levelQMul := len(ringQMul.Modulus) - 1

	for i := 0; i < 2; i++ {
		ringQ.MulScalarBigint(ct0.Value[i], ringQMul.ModulusAtLevel[levelQ], ctOut[i].Q)
		ctOut[i].P.Zero()
		eval.conv.ModDownQPtoQ(levelQ, levelQMul, ctOut[i].Q, ctOut[i].P, ctOut[i].P)
		eval.conv.ModUpPtoQ(levelQMul, levelQ, ctOut[i].P, ctOut[i].Q)

		ringQ.NTT(ctOut[i].Q, ctOut[i].Q)
		ringQMul.NTT(ctOut[i].P, ctOut[i].P)

		ringQ.MForm(ctOut[i].Q, ctOut[i].Q)
		ringQMul.MForm(ctOut[i].P, ctOut[i].P)
	}
}

// tensorAndRescale computes (ct0 x ct1) * (t/Q) and stores the result in ctOut.
func (eval *MEvaluator) tensorAndRescale(ct0, ct1, ctOut *rlwe.Ciphertext) {
	params := eval.params
	ringQ := params.RingQ()
	ringQMul := params.RingQMul()
	levelQ := len(ringQ.Modulus) - 1
	levelQMul := len(ringQMul.Modulus) - 1

	eval.poolQ[0].Copy(ct0.Value[0])
	eval.poolQ[1].Copy(ct0.Value[1])
	eval.poolQ[2].Copy(ct1.Value[0])
	eval.poolQ[3].Copy(ct1.Value[1])

	// rescale ct0 by Q'/Q
	for i := 0; i < 2; i++ {
		ringQ.MulScalarBigint(eval.poolQ[i], ringQMul.ModulusAtLevel[len(ringQMul.Modulus)-1], eval.poolQ[i])
		ringQMul.MulScalar(eval.poolQMul[i], 0, eval.poolQMul[i])
		eval.conv.ModDownQPtoP(levelQ, levelQMul, eval.poolQ[i], eval.poolQMul[i], eval.poolQMul[i])
		eval.conv.ModUpPtoQ(levelQMul, levelQ, eval.poolQMul[i], eval.poolQ[i])

		ringQ.NTT(eval.poolQ[i], eval.poolQ[i])
		ringQMul.NTT(eval.poolQMul[i], eval.poolQMul[i])

		ringQ.MForm(eval.poolQ[i], eval.poolQ[i])
		ringQMul.MForm(eval.poolQMul[i], eval.poolQMul[i])
	}

	// mod UP ct1
	for i := 2; i < 4; i++ {
		eval.conv.ModUpQtoP(levelQ, levelQMul, eval.poolQ[i], eval.poolQMul[i])

		ringQ.NTT(eval.poolQ[i], eval.poolQ[i])
		ringQMul.NTT(eval.poolQMul[i], eval.poolQMul[i])
	}

	// compute degree 0
	ringQ.MulCoeffsMontgomery(eval.poolQ[0], eval.poolQ[2], eval.poolQ[4])
	ringQMul.MulCoeffsMontgomery(eval.poolQMul[0], eval.poolQMul[2], eval.poolQMul[4])

	// compute degree 1
	ringQ.MulCoeffsMontgomery(eval.poolQ[0], eval.poolQ[3], eval.poolQ[5])
	ringQMul.MulCoeffsMontgomery(eval.poolQMul[0], eval.poolQMul[3], eval.poolQMul[5])

	ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[1], eval.poolQ[2], eval.poolQ[5])
	ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQMul[1], eval.poolQMul[2], eval.poolQMul[5])

	// compute degree 2
	ringQ.MulCoeffsMontgomery(eval.poolQ[1], eval.poolQ[3], eval.poolQ[6])
	ringQMul.MulCoeffsMontgomery(eval.poolQMul[1], eval.poolQMul[3], eval.poolQMul[6])

	// rescale by (X^d-b)/Q
	for i := 0; i < 3; i++ {
		ringQ.InvNTT(eval.poolQ[i+4], eval.poolQ[i+4])
		ringQMul.InvNTT(eval.poolQMul[i+4], eval.poolQMul[i+4])
		eval.conv.ModDownQPtoQ(levelQ, levelQMul, eval.poolQ[i+4], eval.poolQMul[i+4], eval.poolQ[i+4])

		ringQ.MultByMonomial(eval.poolQ[i+4], params.Slots(), ctOut.Value[i])
		ringQ.MulScalarBigint(eval.poolQ[i+4], params.B(), eval.poolQ[i+4])
		ringQ.Sub(ctOut.Value[i], eval.poolQ[i+4], ctOut.Value[i])
	}
}

// tensorAndRescaleHoisted computes (ct0 x ct1) * (t/Q) and stores the result in ctOut.
// ct0 should be created with ExtendQMulLeft and ct1 with ExtendQMulRight.
func (eval *MEvaluator) tensorAndRescaleHoisted(ct0 []ringqp.Poly, ct1, ctOut *rlwe.Ciphertext) {
	ringQ := eval.params.RingQ()
	ringQMul := eval.params.RingQMul()
	levelQ := len(ringQ.Modulus) - 1
	levelQMul := len(ringQMul.Modulus) - 1

	for i := 2; i < 4; i++ {
		eval.poolQ[i].Copy(ct1.Value[i-2])
		eval.conv.ModUpQtoP(levelQ, levelQMul, eval.poolQ[i], eval.poolQMul[i])

		ringQ.NTT(eval.poolQ[i], eval.poolQ[i])
		ringQMul.NTT(eval.poolQMul[i], eval.poolQMul[i])
	}

	ringQ.MulCoeffsMontgomery(ct0[0].Q, eval.poolQ[0], eval.poolQ[4])
	ringQMul.MulCoeffsMontgomery(ct0[0].P, eval.poolQMul[0], eval.poolQMul[4])

	ringQ.MulCoeffsMontgomery(ct0[0].Q, eval.poolQ[1], eval.poolQ[5])
	ringQMul.MulCoeffsMontgomery(ct0[0].P, eval.poolQMul[1], eval.poolQMul[5])

	ringQ.MulCoeffsMontgomeryAndAdd(ct0[1].Q, eval.poolQ[0], eval.poolQ[5])
	ringQMul.MulCoeffsMontgomeryAndAdd(ct0[1].P, eval.poolQMul[0], eval.poolQMul[5])

	ringQ.MulCoeffsMontgomery(ct0[1].Q, eval.poolQ[0], eval.poolQ[6])
	ringQMul.MulCoeffsMontgomery(ct0[1].P, eval.poolQMul[0], eval.poolQMul[6])

	for i := 0; i < 3; i++ {
		ringQ.InvNTT(eval.poolQ[i+4], eval.poolQ[i+4])
		ringQMul.InvNTT(eval.poolQMul[i+4], eval.poolQMul[i+4])
		eval.conv.ModDownQPtoQ(levelQ, levelQMul, eval.poolQ[i+4], eval.poolQMul[i+4], eval.poolQ[i+4])

		ringQ.MultByMonomial(eval.poolQ[i+4], eval.params.Slots(), ctOut.Value[i])
		ringQ.MulScalarBigint(eval.poolQ[i+4], eval.params.B(), eval.poolQ[i+4])
		ringQ.Sub(ctOut.Value[i], eval.poolQ[i+4], ctOut.Value[i])
	}
}

// Add adds op0 to op1 and returns the result in ctOut.
func (eval *MEvaluator) Add(op0, op1, ctOut *Ciphertext) {
	el0, el1, elOut := eval.getElemAndCheckBinary(op0.Ciphertext, op1.Ciphertext,
		ctOut.Ciphertext, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.evaluateInPlaceBinary(el0, el1, elOut, eval.params.RingQ().Add)
}

// AddNew adds op0 to op1 and creates a new element ctOut to store the result.
func (eval *MEvaluator) AddNew(op0, op1 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.Add(op0, op1, ctOut)
	return
}

func (eval *MEvaluator) PlaintextAdd(ct *Ciphertext, pt *Plaintext, ctOut *Ciphertext) {
	el0, el1, elOut := eval.getElemAndCheckBinary(ct.Ciphertext, pt, ctOut.Ciphertext, utils.MaxInt(ct.Degree(), pt.Degree()))
	eval.evaluateInPlaceBinary(el0, el1, elOut, eval.params.RingQ().Add)
}

func (eval *MEvaluator) PlaintextAddNew(ct *Ciphertext, pt *Plaintext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, utils.MaxInt(ct.Degree(), pt.Degree()))
	eval.PlaintextAdd(ct, pt, ctOut)
	return
}

// Sub subtracts op1 from op0 and returns the result in cOut.
func (eval *MEvaluator) Sub(op0, op1, ctOut *Ciphertext) {
	el0, el1, elOut := eval.getElemAndCheckBinary(op0.Ciphertext, op1.Ciphertext,
		ctOut.Ciphertext, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.evaluateInPlaceBinary(el0, el1, elOut, eval.params.RingQ().Sub)

	if el0.Degree() < el1.Degree() {
		for i := el0.Degree() + 1; i < el1.Degree()+1; i++ {
			eval.params.RingQ().Neg(ctOut.Value[i], ctOut.Value[i])
		}
	}
}

// SubNew subtracts op1 from op0 and creates a new element ctOut to store the result.
func (eval *MEvaluator) SubNew(op0, op1 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.Sub(op0, op1, ctOut)
	return
}

// Neg negates op and returns the result in ctOut.
func (eval *MEvaluator) Neg(ctIn, ctOut *Ciphertext) {
	for i := 0; i <= ctIn.Degree(); i++ {
		eval.params.RingQ().Neg(ctIn.Value[i], ctOut.Value[i])
	}
}

// NegNew negates op and creates a new element to store the result.
func (eval *MEvaluator) NegNew(ctIn *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ctIn.Degree())
	eval.Neg(ctIn, ctOut)
	return ctOut
}

// RotateColumns rotates the columns of ct0 by k positions to the left and returns the result in ctOut. As an additional input it requires a RotationKeys struct:
//
// - it must either store all the left and right power-of-2 rotations or the specific rotation that is requested.
//
// If only the power-of-two rotations are stored, the numbers k and n/2-k will be decomposed in base-2 and the rotation with the lowest
// hamming weight will be chosen; then the specific rotation will be computed as a sum of powers of two rotations.
func (eval *MEvaluator) RotateColumns(ct0 *Ciphertext, rtks *rlwe.RotationKeySet, k int, ctOut *Ciphertext) {

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot RotateColumns: input and or output must be of degree 1")
	}

	if k == 0 {

		ctOut.Copy(ct0.El())

	} else {
		galElL := eval.params.GaloisElementForColumnRotationBy(uint64(k))
		// Looks in the rotation key if the corresponding rotation has been generated or if the input is a plaintext
		if swk, inSet := rtks.GetRotationKey(galElL); inSet {

			eval.permute(ct0, galElL, swk, ctOut)

		} else {
			panic(fmt.Errorf("MEvaluator has no rotation key for rotation by %d", k))
		}
	}
}

// RotateColumnsNew applies RotateColumns and returns the result in a new Ciphertext.
func (eval *MEvaluator) RotateColumnsNew(ct0 *Ciphertext, rtks *rlwe.RotationKeySet, k int) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1)
	eval.RotateColumns(ct0, rtks, k, ctOut)
	return
}

// Mul multiplies op0 by op1 and returns the result in ctOut.
func (eval *MEvaluator) MulAndRelin(op0, op1 *Ciphertext, rlk *RelinearizationKey, ctOut *Ciphertext) {
	eval.tensorAndRescale(op0.Ciphertext, op1.Ciphertext, eval.poolCtMul.Ciphertext)
	eval.relinearize(eval.poolCtMul, rlk, ctOut)
}

// Mul multiplies op0 by op1 and returns the result in ctOut.
func (eval *MEvaluator) MulAndRelinNew(op0, op1 *Ciphertext, rlk *RelinearizationKey) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1)
	eval.MulAndRelin(op0, op1, rlk, ctOut)
	return
}

// MulAndRelinHoisted multiplies op0 by op1 and returns the result in ctOut.
// op0 should be created with ExtendQMulLeft and op1 with ExtendQMulRight.
func (eval *MEvaluator) MulAndRelinHoisted(op0 []ringqp.Poly, op1 *Ciphertext, rlk *RelinearizationKey, ctOut *Ciphertext) {
	eval.tensorAndRescaleHoisted(op0, op1.Ciphertext, eval.poolCtMul.Ciphertext)
	eval.relinearize(eval.poolCtMul, rlk, ctOut)
}

func (eval *MEvaluator) tensorAndRescalePt(ct *rlwe.Ciphertext, pt *rlwe.Plaintext, ctOut *rlwe.Ciphertext) {
	params := eval.params
	ringQ := params.RingQ()
	ringQMul := params.RingQMul()
	levelQ := len(ringQ.Modulus) - 1
	levelQMul := len(ringQMul.Modulus) - 1

	eval.poolQ[0].Copy(ct.Value[0])
	eval.poolQ[1].Copy(ct.Value[1])
	eval.poolQ[2].Copy(pt.Value)

	// rescale ct0 by Q'/Q
	for i := 0; i < 2; i++ {
		ringQ.MulScalarBigint(eval.poolQ[i], ringQMul.ModulusAtLevel[len(ringQMul.Modulus)-1], eval.poolQ[i])
		ringQMul.MulScalar(eval.poolQMul[i], 0, eval.poolQMul[i])
		eval.conv.ModDownQPtoP(levelQ, levelQMul, eval.poolQ[i], eval.poolQMul[i], eval.poolQMul[i])
		eval.conv.ModUpPtoQ(levelQMul, levelQ, eval.poolQMul[i], eval.poolQ[i])

		ringQ.NTT(eval.poolQ[i], eval.poolQ[i])
		ringQMul.NTT(eval.poolQMul[i], eval.poolQMul[i])

		ringQ.MForm(eval.poolQ[i], eval.poolQ[i])
		ringQMul.MForm(eval.poolQMul[i], eval.poolQMul[i])
	}

	// mod UP ct1
	eval.conv.ModUpQtoP(levelQ, levelQMul, eval.poolQ[2], eval.poolQMul[2])

	ringQ.NTT(eval.poolQ[2], eval.poolQ[2])
	ringQMul.NTT(eval.poolQMul[2], eval.poolQMul[2])

	eval.poolQ[4].Zero()
	eval.poolQMul[4].Zero()
	eval.poolQ[5].Zero()
	eval.poolQMul[5].Zero()

	ringQ.MulCoeffsMontgomery(eval.poolQ[0], eval.poolQ[2], eval.poolQ[4])
	ringQMul.MulCoeffsMontgomery(eval.poolQMul[0], eval.poolQMul[2], eval.poolQMul[4])

	ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[1], eval.poolQ[2], eval.poolQ[5])
	ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQMul[1], eval.poolQMul[2], eval.poolQMul[5])

	// rescale by (X^d-b)/Q
	for i := 0; i < 2; i++ {
		ringQ.InvNTT(eval.poolQ[i+4], eval.poolQ[i+4])
		ringQMul.InvNTT(eval.poolQMul[i+4], eval.poolQMul[i+4])
		eval.conv.ModDownQPtoQ(levelQ, levelQMul, eval.poolQ[i+4], eval.poolQMul[i+4], eval.poolQ[i+4])

		ringQ.MultByMonomial(eval.poolQ[i+4], params.Slots(), ctOut.Value[i])
		ringQ.MulScalarBigint(eval.poolQ[i+4], params.B(), eval.poolQ[i+4])
		ringQ.Sub(ctOut.Value[i], eval.poolQ[i+4], ctOut.Value[i])
	}
}

func (eval *MEvaluator) PlaintextMul(ct *Ciphertext, pt *Plaintext, ctOut *Ciphertext) {
	eval.tensorAndRescalePt(ct.Ciphertext, pt.Plaintext, ctOut.Ciphertext)
}

func (eval *MEvaluator) PlaintextMulNew(ct *Ciphertext, pt *Plaintext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1)
	eval.PlaintextMul(ct, pt, ctOut)
	return ctOut
}
