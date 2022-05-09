// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// 从汇编源码编译成字节码的过程
// ch := Lex(source,false)
// c := NewCompiler(false)
// c.Feed(ch)
// output, err := c.Compile()

package asm

import (
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/core/vm"
)

// Compiler contains information about the parsed source
// and holds the tokens for the program.
type Compiler struct {
	// 保存在Feed从管道读入的所有token
	tokens []token
	binary []interface{}

	// 记录label定义的位置
	labels map[string]int

	// pos记录读取token的位置
	pc, pos int

	debug bool
}

// newCompiler returns a new allocated compiler.
// 创建新的编译对象,输入代表是否开启Debug
func NewCompiler(debug bool) *Compiler {
	return &Compiler{
		labels: make(map[string]int),
		debug:  debug,
	}
}

// Feed feeds tokens in to ch and are interpreted by
// the compiler.
//
// feed is the first pass in the compile stage as it
// collects the used labels in the program and keeps a
// program counter which is used to determine the locations
// of the jump dests. The labels can than be used in the
// second stage to push labels and determine the right
// position.
// 从输入管道中读取词法分析器解析的token
func (c *Compiler) Feed(ch <-chan token) {
	var prev token
	// pc记录识别到当前token编译出来的字节码长度
	for i := range ch {
		switch i.typ {
		case number:
			num := math.MustParseBig256(i.text).Bytes()
			if len(num) == 0 {
				num = []byte{0}
			}
			c.pc += len(num)
		// -2是去掉两个引号
		case stringValue:
			c.pc += len(i.text) - 2
		// 指令占用一个字节
		case element:
			c.pc++
		// labelDef生成一个JUMPDEST指令,占用一个字节
		case labelDef:
			c.labels[i.text] = c.pc
			c.pc++
		case label:
			c.pc += 4
			// JUMP会额外生成一个PUSH指令,多占用一个字节
			if prev.typ == element && isJump(prev.text) {
				c.pc++
			}
		}

		// 所有输入的token都被记录下来
		c.tokens = append(c.tokens, i)
		prev = i
	}
	if c.debug {
		fmt.Fprintln(os.Stderr, "found", len(c.labels), "labels")
	}
}

// Compile compiles the current tokens and returns a
// binary string that can be interpreted by the EVM
// and an error if it failed.
//
// compile is the second stage in the compile phase
// which compiles the tokens to EVM instructions.
func (c *Compiler) Compile() (string, []error) {
	var errors []error
	// continue looping over the tokens until
	// the stack has been exhausted.
	for c.pos < len(c.tokens) {
		if err := c.compileLine(); err != nil {
			errors = append(errors, err)
		}
	}

	// turn the binary to hex
	// 从binary字段解析出来最终的字节码
	var bin string
	for _, v := range c.binary {
		switch v := v.(type) {
		case vm.OpCode:
			bin += fmt.Sprintf("%x", []byte{byte(v)})
		case []byte:
			bin += fmt.Sprintf("%x", v)
		}
	}
	return bin, errors
}

// next returns the next token and increments the
// position.
func (c *Compiler) next() token {
	token := c.tokens[c.pos]
	c.pos++
	return token
}

// compileLine compiles a single line instruction e.g.
// "push 1", "jump @label".
// 编译一行指令
// 每一行只有两种类型
//   xxx:  定义label
//   OpCode xx 操作码加上参数
func (c *Compiler) compileLine() error {
	n := c.next()
	// 第一个token必须是lineStart
	if n.typ != lineStart {
		return compileErr(n, n.typ.String(), lineStart.String())
	}
	// 验证完lineStart了,读取下一个token
	lvalue := c.next()
	switch lvalue.typ {
	case eof:
		return nil
	// 一行代码要么是element,要么是labelDef
	case element:
		if err := c.compileElement(lvalue); err != nil {
			return err
		}
	case labelDef:
		c.compileLabel()
	case lineEnd:
		return nil
	default:
		return compileErr(lvalue, lvalue.text, fmt.Sprintf("%v or %v", labelDef, element))
	}

	// 识别完上面的之后必须到行尾
	if n := c.next(); n.typ != lineEnd {
		return compileErr(n, n.text, lineEnd.String())
	}

	return nil
}

// compileNumber compiles the number to bytes
// 将数字的字节数组加入Compiler.binary
func (c *Compiler) compileNumber(element token) (int, error) {
	// 将字符串转换成数字并保存成字节数组
	num := math.MustParseBig256(element.text).Bytes()
	if len(num) == 0 {
		num = []byte{0}
	}
	c.pushBin(num)
	return len(num), nil
}

// compileElement compiles the element (push & label or both)
// to a binary representation and may error if incorrect statements
// where fed.
// 只允许JUMP或者PUSH后面加上参数
// 其他任何指令都只能有一个名称,后面就是lineEnd
func (c *Compiler) compileElement(element token) error {
	// check for a jump. jumps must be read and compiled
	// from right to left.
	// 要先读取JUMP后面的内容,然后在加入JUMP指令
	if isJump(element.text) {
		rvalue := c.next()
		switch rvalue.typ {
		// JUMP 123
		case number:
			// TODO figure out how to return the error properly
			c.compileNumber(rvalue)
		// JUMP "xxx"
		case stringValue:
			// strings are quoted, remove them.
			c.pushBin(rvalue.text[1 : len(rvalue.text)-2])
		// JUMP @label
		case label:
			// label的位置使用4个字节表示
			c.pushBin(vm.PUSH4)
			pos := big.NewInt(int64(c.labels[rvalue.text])).Bytes()
			pos = append(make([]byte, 4-len(pos)), pos...)
			c.pushBin(pos)
		case lineEnd:
			c.pos--
		default:
			return compileErr(rvalue, rvalue.text, "number, string or label")
		}
		// push the operation
		// 最终加入JUMP指令
		c.pushBin(toBinary(element.text))
		return nil
	} else if isPush(element.text) {
		// handle pushes. pushes are read from left to right.
		var value []byte

		rvalue := c.next()
		switch rvalue.typ {
		case number:
			value = math.MustParseBig256(rvalue.text).Bytes()
			if len(value) == 0 {
				value = []byte{0}
			}
		case stringValue:
			value = []byte(rvalue.text[1 : len(rvalue.text)-1])
		case label:
			value = big.NewInt(int64(c.labels[rvalue.text])).Bytes()
			value = append(make([]byte, 4-len(value)), value...)
		default:
			return compileErr(rvalue, rvalue.text, "number, string or label")
		}

		if len(value) > 32 {
			return fmt.Errorf("%d type error: unsupported string or number with size > 32", rvalue.lineno)
		}

		// 根据传入参数的长度,计算使用PUSH几指令
		c.pushBin(vm.OpCode(int(vm.PUSH1) - 1 + len(value)))
		c.pushBin(value)
	} else {
		c.pushBin(toBinary(element.text))
	}

	return nil
}

// compileLabel pushes a jumpdest to the binary slice.
// label定义的地方就是一个JUMPDEST
// Compiler.binary新增一个JUMPDEST指令
func (c *Compiler) compileLabel() {
	c.pushBin(vm.JUMPDEST)
}

// pushBin pushes the value v to the binary stack.
// Compiler.binary增加对象v
func (c *Compiler) pushBin(v interface{}) {
	if c.debug {
		fmt.Printf("%d: %v\n", len(c.binary), v)
	}
	c.binary = append(c.binary, v)
}

// isPush returns whether the string op is either any of
// push(N).
// 判断是不是PUSH指令
func isPush(op string) bool {
	return strings.ToUpper(op) == "PUSH"
}

// isJump returns whether the string op is jump(i)
// 判断是不JUMP1或者JUMP指令
func isJump(op string) bool {
	return strings.ToUpper(op) == "JUMPI" || strings.ToUpper(op) == "JUMP"
}

// toBinary converts text to a vm.OpCode
// 输入指令的字符串,转换为byte类型
func toBinary(text string) vm.OpCode {
	return vm.StringToOp(strings.ToUpper(text))
}

// 编译错误对象
type compileError struct {
	got  string
	want string

	lineno int
}

// 错误字符串
func (err compileError) Error() string {
	return fmt.Sprintf("%d syntax error: unexpected %v, expected %v", err.lineno, err.got, err.want)
}

func compileErr(c token, got, want string) error {
	return compileError{
		got:    got,
		want:   want,
		lineno: c.lineno,
	}
}
