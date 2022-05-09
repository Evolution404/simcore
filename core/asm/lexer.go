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
// 提供Lex函数进行词法分析,输入源码返回管道接收被切分好的token

package asm

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// stateFn is used through the lifetime of the
// lexer to parse the different values at the
// current state.
// 类型递归
type stateFn func(*lexer) stateFn


// token is emitted when the lexer has discovered
// a new parsable token. These are delivered over
// the tokens channels of the lexer
type token struct {
	typ    tokenType
	// token在代码中出现的行
	lineno int
	// 具体在代码中这个token的内容
	text   string
}

// tokenType are the different types the lexer
// is able to parse and return.
// 用一个整数保存token的类型
type tokenType int

const (
	eof              tokenType = iota // end of file
	lineStart                         // emitted when a line starts
	lineEnd                           // emitted when a line ends
	invalidStatement                  // any invalid statement
	element                           // any element during element parsing
	// @xxx 是label,编译的时候@xxx会被解析成labelDef的位置
	label                             // label is emitted when a label is found
	// xxx: 是labelDef
	labelDef                          // label definition is emitted when a new label is found
	number                            // number is emitted when a number is found
	stringValue                       // stringValue is emitted when a string has been found

	Numbers            = "1234567890"                                           // characters representing any decimal number
	HexadecimalNumbers = Numbers + "aAbBcCdDeEfF"                               // characters representing any hexadecimal
	Alpha              = "abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ" // characters representing alphanumeric
)

// String implements stringer
// 实现Stringer接口,打印tokentype直接出现类型的字符串
func (it tokenType) String() string {
	if int(it) > len(stringtokenTypes) {
		return "invalid"
	}
	return stringtokenTypes[it]
}

// 从int类型获取token类型的字符串
var stringtokenTypes = []string{
	// 下面的常量都是数字,表示数组的下标
	eof:              "EOF",
	invalidStatement: "invalid statement",
	element:          "element",
	lineEnd:          "end of line",
	lineStart:        "new line",
	label:            "label",
	labelDef:         "label definition",
	number:           "number",
	stringValue:      "string",
}

// lexer is the basic construct for parsing
// source code and turning them in to tokens.
// Tokens are interpreted by the compiler.
// 词法分析器,从源码转化为token
type lexer struct {
	// 源码的字符串表示
	input string // input contains the source code of the program

	// 读取到token通过管道向外发送
	tokens chan token // tokens is used to deliver tokens to the listener
	state  stateFn    // the current state function

	lineno            int // current line number in the source file
	start, pos, width int // positions for lexing and returning value

	debug bool // flag for triggering debug output
}

// lex lexes the program by name with the given source. It returns a
// channel on which the tokens are delivered.
// 输入源码,返回一个管道接收token
func Lex(source []byte, debug bool) <-chan token {
	ch := make(chan token)
	l := &lexer{
		input:  string(source),
		tokens: ch,
		state:  lexLine,
		debug:  debug,
	}
	go func() {
		l.emit(lineStart)
		for l.state != nil {
			l.state = l.state(l)
		}
		l.emit(eof)
		close(l.tokens)
	}()

	return ch
}
// next,backup,peek都是针对单个字符进行操作
// 读取一个token的过程就是,调用若干次next,判断读取完成传入token类型调用emit

// next returns the next rune in the program's source.
// 从源码中解析一个字符,返回读取到的字符
// l.width代表读取到字符的长度,l.pos自动移动到下一个字符开头
func (l *lexer) next() (rune rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return 0
	}
	// 使用utf8编码读取一个字符,width代表这个字符使用了几个字节
	rune, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return rune
}

// backup backsup the last parsed element (multi-character)
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek returns the next rune but does not advance the seeker
// 返回下一个符号,但是pos的标记位置不变
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// ignore advances the seeker and ignores the value
// 跳过当前读取的内容,start=pos
func (l *lexer) ignore() {
	l.start = l.pos
}

// Accepts checks whether the given input matches the next rune
// 判断下一个符号在不在valid中
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}

	l.backup()

	return false
}

// acceptRun will continue to advance the seeker until valid
// can no longer be met.
// 跳过所有满足valid的字符,指向第一个不满足valid的字符
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// acceptRunUntil is the inverse of acceptRun and will continue
// to advance the seeker until the rune has been found.
// 指向第一次满足until的下一个字符,返回false就代表没找到
func (l *lexer) acceptRunUntil(until rune) bool {
	// Continues running until a rune is found
	for i := l.next(); !strings.ContainsRune(string(until), i); i = l.next() {
		if i == 0 {
			return false
		}
	}

	return true
}

// blob returns the current value
// 返回当前token的字符串内容(从start到pos位置)
func (l *lexer) blob() string {
	return l.input[l.start:l.pos]
}

// Emits a new token on to token channel for processing
// 当前已经读取完成了一个token
// 每读取完成一个token都要调用emit,start被重置到下一个符号开头
// 传入token的类型,向tokens管道发送读取到的token
func (l *lexer) emit(t tokenType) {
	token := token{t, l.lineno, l.blob()}

	if l.debug {
		fmt.Fprintf(os.Stderr, "%04d: (%-20v) %s\n", token.lineno, token.typ, token.text)
	}

	l.tokens <- token
	l.start = l.pos
}

// lexLine is state function for lexing lines
func lexLine(l *lexer) stateFn {
	for {
		switch r := l.next(); {
		case r == '\n':
			// lineEnd的token.text就只有一个'\n'
			l.emit(lineEnd)
			// ignore后l.start指向下一行的第一个字符
			l.ignore()
			l.lineno++

			// lineStart并没有实体的符号,token.text是一个空字符串
			l.emit(lineStart)
		// ;; 代表注释
		case r == ';' && l.peek() == ';':
			return lexComment
		case isSpace(r):
			l.ignore()
		// 识别变量名
		case isLetter(r) || r == '_':
			return lexElement
		case isNumber(r):
			return lexNumber
		case r == '@':
			l.ignore()
			return lexLabel
		case r == '"':
			return lexInsideString
		// 结束状态,next返回了0
		default:
			return nil
		}
	}
}

// lexComment parses the current position until the end
// of the line and discards the text.
// 对于注释直接跳过这一整行,lineEnd也不会识别
func lexComment(l *lexer) stateFn {
	l.acceptRunUntil('\n')
	l.ignore()

	return lexLine
}

// lexLabel parses the current label, emits and returns
// the lex text state function to advance the parsing
// process.
// l.input[l.pos-1]一定是'@'
func lexLabel(l *lexer) stateFn {
	l.acceptRun(Alpha + "_" + Numbers)
	l.emit(label)

	return lexLine
}

// lexInsideString lexes the inside of a string until
// the state function finds the closing quote.
// It returns the lex text state function.
// 识别一个字符串字面量
func lexInsideString(l *lexer) stateFn {
	// 匹配下一个引号
	if l.acceptRunUntil('"') {
		l.emit(stringValue)
	}

	return lexLine
}

// 识别一个数字
func lexNumber(l *lexer) stateFn {
	acceptance := Numbers
	if l.accept("xX") {
		acceptance = HexadecimalNumbers
	}
	l.acceptRun(acceptance)

	l.emit(number)

	return lexLine
}

func lexElement(l *lexer) stateFn {
	l.acceptRun(Alpha + "_" + Numbers)

	// 识别labelDef
	if l.peek() == ':' {
		l.emit(labelDef)

		l.accept(":")
		l.ignore()
	} else {
		// 普通的element类型
		l.emit(element)
	}
	return lexLine
}

// 判断是不是字母
func isLetter(t rune) bool {
	return unicode.IsLetter(t)
}

// 判断是不是空白符号
func isSpace(t rune) bool {
	return unicode.IsSpace(t)
}

// 判断是不是数字
func isNumber(t rune) bool {
	return unicode.IsNumber(t)
}
