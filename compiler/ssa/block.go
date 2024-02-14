//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"io"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Block implements a basic block.
type Block struct {
	ID         BlockID
	Name       string
	From       []*Block
	Next       *Block
	BranchCond Value
	Branch     *Block
	Instr      []Instr
	Bindings   *Bindings
	Dead       bool
	Processed  bool
}

// BlockID defines unique block IDs.
type BlockID int

func (id BlockID) String() string {
	return fmt.Sprintf("l%d", id)
}

func (b *Block) String() string {
	return b.ID.String()
}

// Equals tests if the argument block is equal to this basic block.
func (b *Block) Equals(o *Block) bool {
	return b.ID == o.ID
}

// SetNext sets the next basic block.
func (b *Block) SetNext(o *Block) {
	if b.Next != nil && b.Next.ID != o.ID {
		panic(fmt.Sprintf("%s.Next already set to %s, now setting to %s",
			b, b.Next, o))
	}
	b.Next = o
	o.addFrom(b)
}

// SetBranch sets the argument block being a branch block for this
// basic block.
func (b *Block) SetBranch(o *Block) {
	if b.Branch != nil && b.Branch.ID != o.ID {
		panic(fmt.Sprintf("%s.Branch already set to %s, now setting to %s",
			b, b.Next, o))
	}
	b.Branch = o
	o.addFrom(b)
}

func (b *Block) addFrom(o *Block) {
	for _, f := range b.From {
		if f.Equals(o) {
			return
		}
	}
	b.From = append(b.From, o)
}

// AddInstr adds an instruction to this basic block.
func (b *Block) AddInstr(instr Instr) {
	instr.Check()
	b.Instr = append(b.Instr, instr)
}

type returnBindingKey struct {
	BlockID BlockID
	Name    string
}

// ReturnBindingValue define return binding value for a return value.
type ReturnBindingValue struct {
	v    Value
	diff bool
	ok   bool
}

// ReturnBindingCTX defines a context for return binding resolve
// operation.
type ReturnBindingCTX struct {
	cache map[returnBindingKey]ReturnBindingValue
}

// Get gets the return binding for the return value in the basic
// block.
func (ctx *ReturnBindingCTX) Get(b *Block, name string) (
	ReturnBindingValue, bool) {
	value, ok := ctx.cache[returnBindingKey{
		BlockID: b.ID,
		Name:    name,
	}]
	return value, ok
}

// Set sets the return binding for the return value in the basic
// block.
func (ctx *ReturnBindingCTX) Set(b *Block, name string, v Value,
	diff, ok bool) {

	ctx.cache[returnBindingKey{
		BlockID: b.ID,
		Name:    name,
	}] = ReturnBindingValue{
		v:    v,
		diff: diff,
		ok:   ok,
	}
}

// NewReturnBindingCTX creates a new return binding resolve context.
func NewReturnBindingCTX() *ReturnBindingCTX {
	return &ReturnBindingCTX{
		cache: make(map[returnBindingKey]ReturnBindingValue),
	}
}

type BindingStackState struct {
	block    *Block
	r        int
	vTrue    Value
	diffTrue bool
	parent   *Block
}

// ReturnBinding returns the return statement binding for the argument
// value. If the block contains a branch and value is modified in both
// branches, the function adds a Phi instruction to resolve the value
// binding after this basic block. The return value diff tells if
// branch return values has different sizes.
func (b *Block) ReturnBinding(ctx *ReturnBindingCTX, name string,
	retBlock *Block, gen *Generator) (v Value, diff, ok bool) {
	return b.returnBinding(ctx, name, retBlock, gen)
}

func (bl *Block) returnBinding(ctx *ReturnBindingCTX, name string,
	retBlock *Block, gen *Generator) (v Value, diff, ok bool) {
	binding, ok := ctx.Get(bl, name)
	if ok {
		return binding.v, binding.diff, binding.ok
	}
	state := &BindingStackState{
		block:  bl,
		r:      0,
		parent: nil,
	}
	stack := []*BindingStackState{state}

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		b := s.block
		stack = stack[:len(stack)-1]

		binding, bok := ctx.Get(b, name)
		if bok {
			v = binding.v
			diff = binding.diff
			ok = binding.ok
		} else {
			if b.Branch == nil || b.Next == b.Branch {
				// Sequential block, return latest value
				if b.Next != nil {
					stack = append(stack, &BindingStackState{
						block:  b.Next,
						r:      1,
						parent: b,
					})
					continue
				} else {
					bind, ok := b.Bindings.Get(name)
					if !ok {
						ctx.Set(b, name, v, false, false)
						diff = false
						ok = false
					} else {
						v = bind.Value(retBlock, gen)
						ctx.Set(b, name, v, false, true)
						diff = false
						ok = true
					}
				}
			} else {
				stack = append(stack, &BindingStackState{
					block: b.Branch,
					r:     2,
				})
				continue
			}
		}

		switch s.r {
		case 1:
			if ok {
				ctx.Set(s.parent, name, v, diff, true)
			} else {
				bind, bok := s.parent.Bindings.Get(name)
				if !bok {
					ctx.Set(s.parent, name, v, false, false)
					diff = false
					ok = false
				} else {
					v = bind.Value(retBlock, gen)
					ctx.Set(s.parent, name, v, false, true)
					diff = false
					ok = true
				}
			}
		case 2:
			if !ok {
				ctx.Set(s.parent, name, v, false, false)
				diff = false
				ok = false
			} else {
				stack = append(stack, &BindingStackState{
					block:    b.Next,
					r:        3,
					vTrue:    v,
					diffTrue: diff,
					parent:   b,
				})
			}
		case 3:
			if !ok {
				ctx.Set(s.parent, name, v, false, false)
				diff = false
				ok = false
			} else {
				if s.vTrue.Equal(&v) {
					ctx.Set(s.parent, name, s.vTrue, s.diffTrue || diff, true)
					v = s.vTrue
					diff = s.diffTrue || diff
					ok = true
				} else {
					var rType types.Info
					if s.vTrue.Type.Bits > v.Type.Bits {
						rType = s.vTrue.Type
					} else {
						rType = v.Type
					}

					vFalse := v
					v = gen.AnonVal(rType)
					retBlock.AddInstr(NewPhiInstr(s.parent.BranchCond, s.vTrue, vFalse, v))

					diff = s.vTrue.Type.Bits != vFalse.Type.Bits || s.diffTrue || diff
					ctx.Set(s.parent, name, v, diff, true)
					ok = true
				}
			}
		}
	}

	return v, diff, ok
}

// Serialize serializes the basic block's instructions.
func (b *Block) Serialize() []Step {
	seen := make(map[BlockID]bool)
	return b.serialize(nil, seen)
}

func (bl *Block) serialize(code []Step, seen map[BlockID]bool) []Step {
	stack := []*Block{bl}
	for len(stack) > 0 {
		b := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if seen[b.ID] {
			continue
		}

		// Have all predecessors been processed?
		for _, from := range b.From {
			if !seen[from.ID] {
				continue
			}
		}
		seen[b.ID] = true

		var label string
		if len(b.Name) > 0 {
			label = b.Name
		}

		for _, instr := range b.Instr {
			code = append(code, Step{
				Label: label,
				Instr: instr,
			})
			label = ""
		}

		if b.Next != nil {
			stack = append(stack, b.Next)
		}
		if b.Branch != nil {
			stack = append(stack, b.Branch)
		}
	}
	return code
}

// DotNodes creates graphviz dot description of this basic block.
func (b *Block) DotNodes(out io.Writer, seen map[BlockID]bool) {
	if seen[b.ID] {
		return
	}
	seen[b.ID] = true

	var label string
	if len(b.Instr) == 1 {
		label = b.Instr[0].string(0, false)
	} else {
		var maxLen int
		for _, i := range b.Instr {
			l := len(i.Op.String())
			if l > maxLen {
				maxLen = l
			}
		}
		for _, i := range b.Instr {
			label += i.string(maxLen, false)
			label += "\\l"
		}
	}

	fmt.Fprintf(out, "  %s [label=\"%s\"]\n", b,
		strings.ReplaceAll(label, `"`, `\"`))

	if b.Next != nil {
		b.Next.DotNodes(out, seen)
	}
	if b.Branch != nil {
		b.Branch.DotNodes(out, seen)
	}
}

// DotLinks creates graphviz dot description of the links to and from
// this basic block.
func (b *Block) DotLinks(out io.Writer, seen map[BlockID]bool) {
	if seen[b.ID] {
		return
	}
	seen[b.ID] = true
	if b.Next != nil {
		fmt.Fprintf(out, "  %s -> %s [label=\"%s\"];\n",
			b, b.Next, b.Next)
	}
	if b.Branch != nil {
		fmt.Fprintf(out, "  %s -> %s [label=\"%s\"];\n",
			b, b.Branch, b.Branch)
	}

	if b.Next != nil {
		b.Next.DotLinks(out, seen)
	}
	if b.Branch != nil {
		b.Branch.DotLinks(out, seen)
	}
}

// Dot creates a graphviz dot description of this basic block.
func Dot(out io.Writer, block *Block) {
	fontname := "Courier"
	fontsize := 10

	fmt.Fprintln(out, "digraph program {")
	fmt.Fprintf(out, "  node [shape=box fontname=\"%s\" fontsize=\"%d\"]\n",
		fontname, fontsize)
	fmt.Fprintf(out, "  edge [fontname=\"%s\" fontsize=\"%d\"]\n",
		fontname, fontsize)
	block.DotNodes(out, make(map[BlockID]bool))
	block.DotLinks(out, make(map[BlockID]bool))
	fmt.Fprintln(out, "}")
}
