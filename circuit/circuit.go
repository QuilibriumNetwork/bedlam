//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"math"
	"math/big"
)

// Operation specifies gate function.
type Operation byte

// Gate functions.
const (
	XOR Operation = iota
	XNOR
	AND
	OR
	INV
	Count
	NumLevels
	MaxWidth
)

// Stats holds statistics about circuit operations.
type Stats [MaxWidth + 1]uint64

// Add adds the argument statistics to this statistics object.
func (stats *Stats) Add(o Stats) {
	for i := XOR; i < Count; i++ {
		stats[i] += o[i]
	}
	stats[Count]++

	for i := NumLevels; i <= MaxWidth; i++ {
		if o[i] > stats[i] {
			stats[i] = o[i]
		}
	}
}

// Count returns the number of gates in the statistics object.
func (stats Stats) Count() uint64 {
	var result uint64
	for i := XOR; i < Count; i++ {
		result += stats[i]
	}
	return result
}

// Cost computes the relative computational cost of the circuit.
func (stats Stats) Cost() uint64 {
	return (stats[AND]+stats[INV])*2 + stats[OR]*3
}

func (stats Stats) String() string {
	var result string

	for i := XOR; i < Count; i++ {
		v := stats[i]
		if len(result) > 0 {
			result += " "
		}
		result += fmt.Sprintf("%s=%d", i, v)
	}
	result += fmt.Sprintf(" xor=%d", stats[XOR]+stats[XNOR])
	result += fmt.Sprintf(" !xor=%d", stats[AND]+stats[OR]+stats[INV])
	result += fmt.Sprintf(" levels=%d", stats[NumLevels])
	result += fmt.Sprintf(" width=%d", stats[MaxWidth])
	return result
}

func (op Operation) String() string {
	switch op {
	case XOR:
		return "XOR"
	case XNOR:
		return "XNOR"
	case AND:
		return "AND"
	case OR:
		return "OR"
	case INV:
		return "INV"
	case Count:
		return "#"
	default:
		return fmt.Sprintf("{Operation %d}", op)
	}
}

// IO specifies circuit input and output arguments.
type IO []IOArg

// Size computes the size of the circuit input and output arguments in
// bits.
func (io IO) Size() int {
	var sum int
	for _, a := range io {
		sum += int(a.Type.Bits)
	}
	return sum
}

func (io IO) String() string {
	var str = ""
	for i, a := range io {
		if i > 0 {
			str += ", "
		}
		if len(a.Name) > 0 {
			str += a.Name + ":"
		}
		str += a.Type.String()
	}
	return str
}

// Split splits the value into separate I/O arguments.
func (io IO) Split(in *big.Int) []*big.Int {
	var result []*big.Int
	var bit int
	for _, arg := range io {
		r := big.NewInt(0)
		for i := 0; i < int(arg.Type.Bits); i++ {
			if in.Bit(bit) == 1 {
				r = big.NewInt(0).SetBit(r, i, 1)
			}
			bit++
		}
		result = append(result, r)
	}
	return result
}

// Circuit specifies a boolean circuit.
type Circuit struct {
	NumGates int
	NumWires int
	Inputs   IO
	Outputs  IO
	Gates    []Gate
	Stats    Stats
}

func (c *Circuit) String() string {
	return fmt.Sprintf("#gates=%d (%s) #w=%d", c.NumGates, c.Stats, c.NumWires)
}

// Cost computes the relative computational cost of the circuit.
func (c *Circuit) Cost() uint64 {
	return c.Stats.Cost()
}

// Dump prints a debug dump of the circuit.
func (c *Circuit) Dump() {
	fmt.Printf("circuit %s\n", c)
	for id, gate := range c.Gates {
		fmt.Printf("%04d\t%s\n", id, gate)
	}
}

// AssignLevels assigns levels for gates. The level desribes how many
// steps away the gate is from input wires.
func (c *Circuit) AssignLevels() {
	levels := make([]Level, c.NumWires)
	countByLevel := make([]uint32, c.NumWires)

	var max Level

	for idx, gate := range c.Gates {
		level := levels[gate.Input0]
		if gate.Op != INV {
			l1 := levels[gate.Input1]
			if l1 > level {
				level = l1
			}
		}
		c.Gates[idx].Level = level
		countByLevel[level]++

		level++

		levels[gate.Output] = level
		if level > max {
			max = level
		}
	}
	c.Stats[NumLevels] = uint64(max)

	var maxWidth uint32
	for _, count := range countByLevel {
		if count > maxWidth {
			maxWidth = count
		}
	}
	if false {
		for i := 0; i < int(max); i++ {
			fmt.Printf("%v,%v\n", i, countByLevel[i])
		}
	}

	c.Stats[MaxWidth] = uint64(maxWidth)
}

// Level defines gate's distance from input wires.
type Level uint32

// Gate specifies a boolean gate.
type Gate struct {
	Input0 Wire
	Input1 Wire
	Output Wire
	Op     Operation
	Level  Level
}

func (g Gate) String() string {
	return fmt.Sprintf("%v %v %v", g.Inputs(), g.Op, g.Output)
}

// Inputs returns gate input wires.
func (g Gate) Inputs() []Wire {
	switch g.Op {
	case XOR, XNOR, AND, OR:
		return []Wire{g.Input0, g.Input1}
	case INV:
		return []Wire{g.Input0}
	default:
		panic(fmt.Sprintf("unsupported gate type %s", g.Op))
	}
}

// Wire specifies a wire ID.
type Wire uint32

// InvalidWire specifies an invalid wire ID.
const InvalidWire Wire = math.MaxUint32

// Int returns the wire ID as integer.
func (w Wire) Int() int {
	return int(w)
}

func (w Wire) String() string {
	return fmt.Sprintf("w%d", w)
}
