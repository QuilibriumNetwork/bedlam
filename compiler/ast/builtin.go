//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package ast

import (
	"fmt"
	"path"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ssa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Builtin implements QCL builtin functions.
type Builtin struct {
	SSA  SSA
	Eval Eval
}

// SSA implements the builtin SSA generation.
type SSA func(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error)

// Eval implements the builtin evaluation in constant folding.
type Eval func(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error)

// Predeclared identifiers.
var builtins = map[string]Builtin{
	"copy": {
		SSA: copySSA,
	},
	"floorPow2": {
		SSA:  floorPow2SSA,
		Eval: floorPow2Eval,
	},
	"len": {
		SSA:  lenSSA,
		Eval: lenEval,
	},
	"native": {
		SSA: nativeSSA,
	},
	"size": {
		SSA:  sizeSSA,
		Eval: sizeEval,
	},
}

func copySSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) != 2 {
		return nil, nil, ctx.Errorf(loc,
			"invalid amount of arguments in call to copy")
	}
	dst := args[0]
	src := args[1]

	var baseName string
	var baseType types.Info
	var baseScope ssa.Scope
	var baseBindings *ssa.Bindings
	var base ssa.Value

	var dstOffset types.Size
	var elementType types.Info

	switch dst.Type.Type {
	case types.TArray:
		baseName = dst.Name
		baseType = dst.Type
		baseScope = dst.Scope
		baseBindings = block.Bindings

		dstOffset = 0
		elementType = *dst.Type.ElementType
		base = dst

	case types.TPtr:
		elementType = *dst.Type.ElementType
		if elementType.Type != types.TArray {
			return nil, nil, ctx.Errorf(loc,
				"setting elements of non-array %s",
				elementType)
		}
		baseName = dst.PtrInfo.Name
		baseType = dst.PtrInfo.ContainerType
		baseScope = dst.PtrInfo.Scope
		baseBindings = dst.PtrInfo.Bindings

		dstOffset = dst.PtrInfo.Offset
		elementType = *elementType.ElementType

		b, ok := baseBindings.Get(baseName)
		if !ok {
			return nil, nil, ctx.Errorf(loc, "undefined: %s", baseName)
		}
		base = b.Value(block, gen)

	default:
		return nil, nil, ctx.Errorf(loc,
			"arguments to copy must be slices; have %s, %s",
			dst.Type.Type, src.Type.Type)
	}

	var srcType types.Info
	if src.Type.Type == types.TPtr {
		srcType = *src.Type.ElementType
	} else {
		srcType = src.Type
	}

	if srcType.Type != types.TArray {
		return nil, nil, ctx.Errorf(loc,
			"second argument to copy should be slice or array (%v)", src.Type)
	}
	if !elementType.Equal(*srcType.ElementType) {
		return nil, nil, ctx.Errorf(loc,
			"arguments to copy have different element types: %s and %s",
			baseType.ElementType, src.Type.ElementType)
	}

	dstBits := dst.Type.Bits
	srcBits := src.Type.Bits

	var copied types.Size
	if srcBits > dstBits {
		fromConst := gen.Constant(int32(0), types.Uint32)
		toConst := gen.Constant(int32(dstBits), types.Uint32)

		tmp := gen.AnonVal(dst.Type)
		block.AddInstr(ssa.NewSliceInstr(src, fromConst, toConst, tmp))
		src = tmp
		srcBits = dstBits

		copied = dst.Type.ArraySize
	} else {
		copied = src.Type.ArraySize
	}

	lValue := gen.NewVal(baseName, baseType, baseScope)

	fromConst := gen.Constant(int32(dstOffset), types.Uint32)
	toConst := gen.Constant(int32(dstOffset+srcBits), types.Uint32)

	block.AddInstr(ssa.NewAmovInstr(src, base, fromConst, toConst, lValue))
	baseBindings.Set(lValue, nil)

	v := gen.Constant(int32(copied), types.Int32)
	gen.AddConstant(v)

	return block, []ssa.Value{v}, nil
}

func floorPow2SSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {
	return nil, nil, ctx.Errorf(loc, "floorPow2SSA not implemented")
}

func floorPow2Eval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to floorPow2")
	}

	constVal, _, err := args[0].Eval(env, ctx, gen)
	if err != nil {
		return ssa.Undefined, false, ctx.Errorf(loc, "%s", err)
	}

	val, err := constVal.ConstInt()
	if err != nil {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"non-integer (%T) argument in %s: %s", constVal, args[0], err)
	}

	var i types.Size
	for i = 1; i <= val; i <<= 1 {
	}
	i >>= 1

	return gen.Constant(int32(i), types.Int32), true, nil
}

func lenSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) != 1 {
		return nil, nil, ctx.Errorf(loc,
			"invalid amount of arguments in call to len")
	}

	var val types.Size
	switch args[0].Type.Type {
	case types.TString:
		val = args[0].Type.Bits / types.ByteBits

	case types.TArray:
		val = args[0].Type.ArraySize

	default:
		return nil, nil, ctx.Errorf(loc, "invalid argument 1 (type %s) for len",
			args[0].Type)
	}

	v := gen.Constant(int32(val), types.Int32)
	gen.AddConstant(v)

	return block, []ssa.Value{v}, nil
}

func lenEval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to len")
	}

	switch arg := args[0].(type) {
	case *VariableRef:
		var typeInfo types.Info

		if len(arg.Name.Package) > 0 {
			// Check if the package name is bound to a value.
			b, ok := env.Get(arg.Name.Package)
			if ok {
				if b.Type.Type != types.TStruct {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"%s undefined", arg.Name)
				}
				ok = false
				for _, f := range b.Type.Struct {
					if f.Name == arg.Name.Name {
						typeInfo = f.Type
						ok = true
						break
					}
				}
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"undefined variable '%s'", arg.Name)
				}
			} else {
				// Resolve name from the package.
				pkg, ok := ctx.Packages[arg.Name.Package]
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"package '%s' not found", arg.Name.Package)
				}
				b, ok := pkg.Bindings.Get(arg.Name.Name)
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"undefined variable '%s'", arg.Name)
				}
				typeInfo = b.Type
			}
		} else {
			b, ok := env.Get(arg.Name.Name)
			if !ok {
				return ssa.Undefined, false, ctx.Errorf(loc,
					"undefined variable '%s'", arg.Name)
			}
			typeInfo = b.Type
		}

		if typeInfo.Type == types.TPtr {
			typeInfo = *typeInfo.ElementType
		}

		switch typeInfo.Type {
		case types.TString:
			return gen.Constant(int32(typeInfo.Bits/types.ByteBits),
				types.Int32), true, nil

		case types.TArray:
			return gen.Constant(int32(typeInfo.ArraySize), types.Int32),
				true, nil

		default:
			return ssa.Undefined, false, ctx.Errorf(loc,
				"invalid argument 1 (type %s) for len", typeInfo)
		}

	default:
		return ssa.Undefined, false, ctx.Errorf(loc,
			"len(%v/%T) is not constant", arg, arg)
	}
}

func nativeSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) < 1 {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	}
	name, ok := args[0].ConstValue.(string)
	if !args[0].Const || !ok {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	}
	// Our native name constant is not needed in the implementation.
	gen.RemoveConstant(args[0])
	args = args[1:]

	switch name {
	case "hamming":
		if len(args) != 2 {
			return nil, nil, ctx.Errorf(loc,
				"invalid amount of arguments in call to '%s'", name)
		}

		var typeInfo types.Info
		for _, arg := range args {
			if arg.Type.Bits > typeInfo.Bits {
				typeInfo = arg.Type
			}
		}

		v := gen.AnonVal(typeInfo)
		block.AddInstr(ssa.NewBuiltinInstr(circuits.Hamming, args[0], args[1],
			v))

		return block, []ssa.Value{v}, nil

	default:
		if circuit.IsFilename(name) {
			return nativeCircuit(name, block, ctx, gen, args, loc)
		}
		return nil, nil, ctx.Errorf(loc, "unknown native '%s'", name)
	}
}

func nativeCircuit(name string, block *ssa.Block, ctx *Codegen,
	gen *ssa.Generator, args []ssa.Value, loc utils.Point) (
	*ssa.Block, []ssa.Value, error) {

	dir := path.Dir(loc.Source)
	fp := path.Join(dir, name)

	var err error

	circ, ok := ctx.Native[fp]
	if !ok {
		circ, err = circuit.Parse(fp)
		if err != nil {
			return nil, nil, ctx.Errorf(loc, "failed to parse circuit: %s", err)
		}
		circ.AssignLevels()
		ctx.Native[fp] = circ
		if ctx.Verbose {
			fmt.Printf(" - native %s: %v\n", name, circ)
		}
	} else if ctx.Verbose {
		fmt.Printf(" - native %s: cached\n", name)
	}

	if len(circ.Inputs) > len(args) {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	} else if len(circ.Inputs) < len(args) {
		return nil, nil, ctx.Errorf(loc, "too many argument in call to native")
	}
	// Check that the argument types match.
	for idx, io := range circ.Inputs {
		arg := args[idx]
		if io.Type.Bits < arg.Type.Bits || io.Type.Bits > arg.Type.Bits &&
			!arg.Const {
			return nil, nil, ctx.Errorf(loc,
				"invalid argument %d for native circuit: got %s, need %d",
				idx, arg.Type, io.Type.Bits)
		}
	}

	var result []ssa.Value

	for _, io := range circ.Outputs {
		result = append(result, gen.AnonVal(types.Info{
			Type:       types.TUndefined,
			IsConcrete: true,
			Bits:       io.Type.Bits,
		}))
	}

	block.AddInstr(ssa.NewCircInstr(args, circ, result))

	return block, result, nil
}

func sizeSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) != 1 {
		return nil, nil, ctx.Errorf(loc,
			"invalid amount of arguments in call to size")
	}

	v := gen.Constant(int32(args[0].Type.Bits), types.Int32)
	gen.AddConstant(v)

	return block, []ssa.Value{v}, nil
}

func sizeEval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to size")
	}

	switch arg := args[0].(type) {
	case *VariableRef:
		var b ssa.Binding
		var ok bool

		if len(arg.Name.Package) > 0 {
			var pkg *Package
			pkg, ok = ctx.Packages[arg.Name.Package]
			if !ok {
				return ssa.Undefined, false, ctx.Errorf(loc,
					"package '%s' not found", arg.Name.Package)
			}
			b, ok = pkg.Bindings.Get(arg.Name.Name)
		} else {
			b, ok = env.Get(arg.Name.Name)
		}
		if !ok {
			return ssa.Undefined, false, ctx.Errorf(loc,
				"undefined variable '%s'", arg.Name.String())
		}
		return gen.Constant(int32(b.Type.Bits), types.Int32), true, nil

	default:
		return ssa.Undefined, false, ctx.Errorf(loc,
			"size(%v/%T) is not constant", arg, arg)
	}
}
