package gov

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
)

type Governance struct {
	epoch uint64
	chain consensus.ChainHeaderReader
}

func New(epoch uint64, chain consensus.ChainHeaderReader) *Governance {
	return &Governance{epoch: epoch, chain: chain}
}

// EpochValidators returns the current epoch validators that height belongs to
func (g *Governance) EpochValidators(height uint64) []common.Address {
	// TODO: get real validators by calling contract
	header := g.chain.GetHeaderByNumber(0)
	return header.NextValidators
}

func (g *Governance) NextValidators(height uint64) []common.Address {
	if height%g.epoch != 0 {
		return []common.Address{}
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators
	default:
		// TODO: get real validators by calling contract, currently use genesis
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators
	}
}

func CompareValidators(lhs, rhs []common.Address) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := 0; i < len(lhs); i++ {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	return true
}

func CompareValidatorPowers(lhs, rhs []uint64) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := 0; i < len(lhs); i++ {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	return true
}

func (g *Governance) NextValidatorPowers(height uint64) []uint64 {
	if height%g.epoch != 0 {
		return []uint64{}
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidatorPowers
	default:
		// TODO get real validators by calling contract
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidatorPowers
	}
}
