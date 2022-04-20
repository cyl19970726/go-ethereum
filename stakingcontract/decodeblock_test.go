package stakingcontract

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"testing"
)

type testBlock struct {
	header *types.Header
}

func TestDecodeBlock(t *testing.T) {

	//validators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa"), common.HexToAddress("0xbb000000000000000000000000000000000000bb"), common.HexToAddress("0xdd000000000000000000000000000000000000bb"), common.HexToAddress("0xcc000000000000000000000000000000000000bb")}
	validators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa")}
	powers := []uint64{1, 2, 3, 4}

	sig1 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: common.HexToAddress("0xaa000000000000000000000000000000000000aa"),
		TimestampMs:      1000,
		Signature:        []byte{1, 2, 3, 4, 5},
	}

	sig2 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: common.HexToAddress("0xbb000000000000000000000000000000000000bb"),
		TimestampMs:      1001,
		Signature:        []byte{1, 2, 3, 4, 5, 6},
	}

	sig3 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: common.HexToAddress("0xcc000000000000000000000000000000000000cc"),
		TimestampMs:      1002,
		Signature:        []byte{1, 2, 3, 4, 5, 6, 7},
	}
	commitData := &types.Commit{
		Height:     100,
		Round:      2,
		BlockID:    common.HexToHash("0xcc000000000000000000000000000000000000000000000000000000000000aa"),
		Signatures: []types.CommitSig{sig1, sig2, sig3},
	}
	header :=
		&types.Header{
			ParentHash:  common.HexToHash("0x112233445566778899001122334455667788990011223344556677889900aabb"),
			UncleHash:   common.HexToHash("0x000033445566778899001122334455667788990011223344556677889900aabb"),
			Coinbase:    common.HexToAddress("0xd76fb45ed105f1851d74233f884d256c4fdad634"),
			Root:        common.HexToHash("0x1100000000000000000000000000000000000000000000000000000000000011"),
			TxHash:      common.HexToHash("0x2200000000000000000000000000000000000000000000000000000000000022"),
			ReceiptHash: common.HexToHash("0x3300000000000000000000000000000000000000000000000000000000000033"),
			Difficulty:  big.NewInt(11000),
			Number:      big.NewInt(10001),
			GasLimit:    900000017326518,
			GasUsed:     8000918271,
			Time:        98765372,
			Extra:       []byte{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2},
			MixDigest:   common.HexToHash("0x4400000000000000000000000000000000000000000000000000000000000044"),
			Nonce:       [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			BaseFee:     big.NewInt(777),

			TimeMs:              827163,
			NextValidators:      validators,
			NextValidatorPowers: powers,
			LastCommitHash:      common.HexToHash("0xcc000000000000000000000000000000000000000000000000000000000000cc"),
			Commit:              commitData,
		}
	headerRlp, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HeaderRLP:", common.Bytes2Hex(headerRlp))
	block := &testBlock{
		header: header,
	}
	if rlpData, err := rlp.EncodeToBytes(block); err != nil {
		t.Fatal(err)
	} else {
		fmt.Println(common.Bytes2Hex(rlpData))
		b := &testBlock{}
		rlp.DecodeBytes(rlpData, b)
	}

}

type testAccount struct {
	Pri  *ecdsa.PrivateKey
	Pub  *ecdsa.PublicKey
	Addr common.Address
}

func pubKeyToAddress(pub []byte) common.Address {
	var addr common.Address
	// the first byte of pubkey is bitcoin heritage
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr
}

func (acc *testAccount) VerifySignature(msg []byte, sig []byte) bool {
	h := crypto.Keccak256Hash(msg)

	pub, err := crypto.Ecrecover(h[:], sig)
	if err != nil {
		return false
	}

	if len(pub) == 0 || pub[0] != 4 {
		return false
	}

	addr := pubKeyToAddress(pub)
	return addr == acc.Addr
}

func newAccount() *testAccount {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return &testAccount{
		Pri:  key,
		Pub:  &key.PublicKey,
		Addr: crypto.PubkeyToAddress(key.PublicKey),
	}

}
func TestVerifyAllSignatures(t *testing.T) {
	acc1 := newAccount()
	acc2 := newAccount()
	acc3 := newAccount()

	sig1 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc1.Addr,
		TimestampMs:      10007281,
	}

	sig2 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc2.Addr,
		TimestampMs:      20017273,
	}

	sig3 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc3.Addr,
		TimestampMs:      13217273,
	}

	nextValidators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa"), common.HexToAddress("0xbb000000000000000000000000000000000000bb"), common.HexToAddress("0xcc000000000000000000000000000000000000cc")}
	//validators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa")}
	powers := []uint64{2, 2, 2}

	header :=
		&types.Header{
			ParentHash:  common.HexToHash("0x112233445566778899001122334455667788990011223344556677889900aabb"),
			UncleHash:   common.HexToHash("0x000033445566778899001122334455667788990011223344556677889900aabb"),
			Coinbase:    common.HexToAddress("0xd76fb45ed105f1851d74233f884d256c4fdad634"),
			Root:        common.HexToHash("0x1100000000000000000000000000000000000000000000000000000000000011"),
			TxHash:      common.HexToHash("0x2200000000000000000000000000000000000000000000000000000000000022"),
			ReceiptHash: common.HexToHash("0x3300000000000000000000000000000000000000000000000000000000000033"),
			Difficulty:  big.NewInt(11000),
			Number:      big.NewInt(10001),
			GasLimit:    900000017326518,
			GasUsed:     8000918271,
			Time:        98765372,
			Extra:       []byte{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2},
			MixDigest:   common.HexToHash("0x4400000000000000000000000000000000000000000000000000000000000044"),
			Nonce:       [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			BaseFee:     big.NewInt(777),

			TimeMs:              827163,
			NextValidators:      nextValidators,
			NextValidatorPowers: powers,
			LastCommitHash:      common.HexToHash("0xcc000000000000000000000000000000000000000000000000000000000000cc"),
		}

	headerHash := header.Hash()
	headerRLP1, _ := rlp.EncodeToBytes(header)
	commitData := &types.Commit{
		Height:     100,
		Round:      2,
		BlockID:    headerHash,
		Signatures: []types.CommitSig{sig1, sig2, sig3},
	}

	msg1 := commitData.VoteSignBytes("evm_3334", 0)
	fmt.Println("vote rlp msg1:", common.Bytes2Hex(msg1))
	hash1 := crypto.Keccak256Hash(msg1)
	msg2 := commitData.VoteSignBytes("evm_3334", 1)
	fmt.Println("vote rlp msg2:", common.Bytes2Hex(msg2))
	hash2 := crypto.Keccak256Hash(msg2)
	msg3 := commitData.VoteSignBytes("evm_3334", 2)
	fmt.Println("vote rlp msg3:", common.Bytes2Hex(msg3))
	hash3 := crypto.Keccak256Hash(msg3)

	var err error
	sig1.Signature, err = crypto.Sign(hash1[:], acc1.Pri)
	if err != nil {
		t.Fatal(err)
	}
	sig2.Signature, err = crypto.Sign(hash2[:], acc2.Pri)
	if err != nil {
		t.Fatal(err)
	}
	sig3.Signature, err = crypto.Sign(hash3[:], acc3.Pri)
	if err != nil {
		t.Fatal(err)
	}
	commitData.Signatures = []types.CommitSig{sig1, sig2, sig3}

	if !acc1.VerifySignature(msg1, sig1.Signature) {
		t.Errorf("sig1 recover fail")
	}

	if !acc2.VerifySignature(msg2, sig2.Signature) {
		t.Errorf("sig2 recover fail")
	}

	if !acc3.VerifySignature(msg3, sig3.Signature) {
		t.Errorf("sig3 recover fail")
	}

	header.Commit = commitData

	fmt.Println("COMMIT:", commitData)
	fmt.Println("sig1:", sig1)
	fmt.Println(common.Bytes2Hex(sig1.Signature))
	fmt.Println("sig2:", sig2)
	fmt.Println(common.Bytes2Hex(sig2.Signature))
	fmt.Println("sig3:", sig3)
	fmt.Println(common.Bytes2Hex(sig3.Signature))

	block := &testBlock{
		header: header,
	}
	if rlpData, err := rlp.EncodeToBytes(block); err != nil {
		t.Fatal(err)
	} else {
		fmt.Println(common.Bytes2Hex(rlpData))
		b := &testBlock{}
		rlp.DecodeBytes(rlpData, b)
	}

	headerRLP2, _ := rlp.EncodeToBytes(header)
	fmt.Println("header rlp1:", common.Bytes2Hex(headerRLP1))
	fmt.Println("header rlp2:", common.Bytes2Hex(headerRLP2))

}

func TestVerifyHeader(t *testing.T) {
	acc1 := newAccount()
	acc2 := newAccount()
	acc3 := newAccount()

	sig1 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc1.Addr,
		TimestampMs:      10007281,
	}

	sig2 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc2.Addr,
		TimestampMs:      20017273,
	}

	sig3 := types.CommitSig{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: acc3.Addr,
		TimestampMs:      13217273,
	}

	nextValidators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa"), common.HexToAddress("0xbb000000000000000000000000000000000000bb"), common.HexToAddress("0xcc000000000000000000000000000000000000cc")}
	//validators := []common.Address{common.HexToAddress("0xaa000000000000000000000000000000000000aa")}
	powers := []uint64{3, 3, 3}

	header :=
		&types.Header{
			ParentHash:  common.HexToHash("0x112233445566778899001122334455667788990011223344556677889900aabb"),
			UncleHash:   common.HexToHash("0x000033445566778899001122334455667788990011223344556677889900aabb"),
			Coinbase:    common.HexToAddress("0xd76fb45ed105f1851d74233f884d256c4fdad634"),
			Root:        common.HexToHash("0x1100000000000000000000000000000000000000000000000000000000000011"),
			TxHash:      common.HexToHash("0x2200000000000000000000000000000000000000000000000000000000000022"),
			ReceiptHash: common.HexToHash("0x3300000000000000000000000000000000000000000000000000000000000033"),
			Difficulty:  big.NewInt(11000),
			Number:      big.NewInt(10001),
			GasLimit:    900000017326518,
			GasUsed:     8000918271,
			Time:        98765372,
			Extra:       []byte{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2},
			MixDigest:   common.HexToHash("0x4400000000000000000000000000000000000000000000000000000000000044"),
			Nonce:       [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			BaseFee:     big.NewInt(777),

			TimeMs:              827163,
			NextValidators:      nextValidators,
			NextValidatorPowers: powers,
			LastCommitHash:      common.HexToHash("0xcc000000000000000000000000000000000000000000000000000000000000cc"),
		}

	headerHash := header.Hash()
	commitData := &types.Commit{
		Height:     100,
		Round:      2,
		BlockID:    headerHash,
		Signatures: []types.CommitSig{sig1, sig2, sig3},
	}

	msg1 := commitData.VoteSignBytes("evm_3334", 0)
	fmt.Println("vote rlp msg1:", common.Bytes2Hex(msg1))
	hash1 := crypto.Keccak256Hash(msg1)
	msg2 := commitData.VoteSignBytes("evm_3334", 1)
	fmt.Println("vote rlp msg2:", common.Bytes2Hex(msg2))
	hash2 := crypto.Keccak256Hash(msg2)
	msg3 := commitData.VoteSignBytes("evm_3334", 2)
	fmt.Println("vote rlp msg3:", common.Bytes2Hex(msg3))
	hash3 := crypto.Keccak256Hash(msg3)

	var err error
	sig1.Signature, err = crypto.Sign(hash1[:], acc1.Pri)
	if err != nil {
		t.Fatal(err)
	}
	sig2.Signature, err = crypto.Sign(hash2[:], acc2.Pri)
	if err != nil {
		t.Fatal(err)
	}
	sig3.Signature, err = crypto.Sign(hash3[:], acc3.Pri)
	if err != nil {
		t.Fatal(err)
	}
	commitData.Signatures = []types.CommitSig{sig1, sig2, sig3}

	if !acc1.VerifySignature(msg1, sig1.Signature) {
		t.Errorf("sig1 recover fail")
	}

	if !acc2.VerifySignature(msg2, sig2.Signature) {
		t.Errorf("sig2 recover fail")
	}

	if !acc3.VerifySignature(msg3, sig3.Signature) {
		t.Errorf("sig3 recover fail")
	}

	fmt.Println("COMMIT:", commitData)
	fmt.Println("sig1:", sig1)
	fmt.Println(common.Bytes2Hex(sig1.Signature))
	fmt.Println("sig2:", sig2)
	fmt.Println(common.Bytes2Hex(sig2.Signature))
	fmt.Println("sig3:", sig3)
	fmt.Println(common.Bytes2Hex(sig3.Signature))

	headerRlp, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HeaderRlp:", common.Bytes2Hex(headerRlp))
	commitRlp, err := rlp.EncodeToBytes(commitData)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("commitRlp:", common.Bytes2Hex(commitRlp))

}
