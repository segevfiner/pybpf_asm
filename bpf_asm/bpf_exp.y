/*
 * BPF asm code parser
 *
 * This program is free software; you can distribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Syntax kept close to:
 *
 * Steven McCanne and Van Jacobson. 1993. The BSD packet filter: a new
 * architecture for user-level packet capture. In Proceedings of the
 * USENIX Winter 1993 Conference Proceedings on USENIX Winter 1993
 * Conference Proceedings (USENIX'93). USENIX Association, Berkeley,
 * CA, USA, 2-2.
 *
 * Copyright 2013 Daniel Borkmann <borkmann@redhat.com>
 * Modified by Segev Finer for pybpf_asm
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

%{

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <linux/filter.h>

#include "bpf_exp.yacc.h"
#include "bpf_exp.flex.h"

enum jmp_type { JTL, JFL, JKL };

typedef struct yyparse_s {
	int curr_instr;
	struct sock_filter *out;
	char **labels, **labels_jt, **labels_jf, **labels_k;
	char *error;
} *yyparse_t;

extern void yyerror(yyscan_t scanner, yyparse_t parser, const char *str);

static int bpf_set_curr_instr(yyscan_t scanner, yyparse_t parser, uint16_t op, uint8_t jt, uint8_t jf, uint32_t k);
static int bpf_set_curr_label(yyscan_t scanner, yyparse_t parser, char *label);
static int bpf_set_jmp_label(yyscan_t scanner, yyparse_t parser, char *label, enum jmp_type type);

%}

%code requires {

#include <stdio.h>
#include <stdbool.h>
#include <linux/filter.h>

typedef void* yyscan_t;
struct yyparse_s;
typedef struct yyparse_s *yyparse_t;

int bpf_asm_compile(const char *str, int len, struct sock_filter **out, char **error);

}

%define api.pure full
%param {yyscan_t scanner}
%parse-param {yyparse_t parser}

%union {
	char *label;
	uint32_t number;
}

%token OP_LDB OP_LDH OP_LD OP_LDX OP_ST OP_STX OP_JMP OP_JEQ OP_JGT OP_JGE
%token OP_JSET OP_ADD OP_SUB OP_MUL OP_DIV OP_AND OP_OR OP_XOR OP_LSH OP_RSH
%token OP_RET OP_TAX OP_TXA OP_LDXB OP_MOD OP_NEG OP_JNEQ OP_JLT OP_JLE OP_LDI
%token OP_LDXI

%token K_PKT_LEN

%token ':' ',' '[' ']' '(' ')' 'x' 'a' '+' 'M' '*' '&' '#' '%'

%token extension number label

%type <label> label
%type <number> extension
%type <number> number

%%

prog
	: line
	| prog line
	;

line
	: instr
	| labelled_instr
	;

labelled_instr
	: labelled instr
	;

instr
	: ldb
	| ldh
	| ld
	| ldi
	| ldx
	| ldxi
	| st
	| stx
	| jmp
	| jeq
	| jneq
	| jlt
	| jle
	| jgt
	| jge
	| jset
	| add
	| sub
	| mul
	| div
	| mod
	| neg
	| and
	| or
	| xor
	| lsh
	| rsh
	| ret
	| tax
	| txa
	;

labelled
	: label ':' { if (bpf_set_curr_label(scanner, parser, $1)) { YYABORT; } }
	;

ldb
	: OP_LDB '[' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_B | BPF_IND, 0, 0, $5)) { YYABORT; } }
	| OP_LDB '[' '%' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_B | BPF_IND, 0, 0, $6)) { YYABORT; } }
	| OP_LDB '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_B | BPF_ABS, 0, 0, $3)) { YYABORT; } }
	| OP_LDB extension {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_B | BPF_ABS, 0, 0,
				   SKF_AD_OFF + $2)) { YYABORT; } }
	;

ldh
	: OP_LDH '[' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_H | BPF_IND, 0, 0, $5)) { YYABORT; } }
	| OP_LDH '[' '%' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_H | BPF_IND, 0, 0, $6)) { YYABORT; } }
	| OP_LDH '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_H | BPF_ABS, 0, 0, $3)) { YYABORT; } }
	| OP_LDH extension {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_H | BPF_ABS, 0, 0,
				   SKF_AD_OFF + $2)) { YYABORT; } }
	;

ldi
	: OP_LDI '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_IMM, 0, 0, $3)) { YYABORT; } }
	| OP_LDI number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_IMM, 0, 0, $2)) { YYABORT; } }
	;

ld
	: OP_LD '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_IMM, 0, 0, $3)) { YYABORT; } }
	| OP_LD K_PKT_LEN {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_W | BPF_LEN, 0, 0, 0)) { YYABORT; } }
	| OP_LD extension {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_W | BPF_ABS, 0, 0,
				   SKF_AD_OFF + $2)) { YYABORT; } }
	| OP_LD 'M' '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_MEM, 0, 0, $4)) { YYABORT; } }
	| OP_LD '[' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_W | BPF_IND, 0, 0, $5)) { YYABORT; } }
	| OP_LD '[' '%' 'x' '+' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_W | BPF_IND, 0, 0, $6)) { YYABORT; } }
	| OP_LD '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LD | BPF_W | BPF_ABS, 0, 0, $3)) { YYABORT; } }
	;

ldxi
	: OP_LDXI '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_IMM, 0, 0, $3)) { YYABORT; } }
	| OP_LDXI number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_IMM, 0, 0, $2)) { YYABORT; } }
	;

ldx
	: OP_LDX '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_IMM, 0, 0, $3)) { YYABORT; } }
	| OP_LDX K_PKT_LEN {
		if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_W | BPF_LEN, 0, 0, 0)) { YYABORT; } }
	| OP_LDX 'M' '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_MEM, 0, 0, $4)) { YYABORT; } }
	| OP_LDXB number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yyerror(scanner, parser, "ldxb offset not supported!");
			YYERROR;
		} else {
			if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_MSH | BPF_B, 0, 0, $6)) { YYABORT; } } }
	| OP_LDX number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yyerror(scanner, parser, "ldxb offset not supported!");
			YYERROR;
		} else {
			if (bpf_set_curr_instr(scanner, parser, BPF_LDX | BPF_MSH | BPF_B, 0, 0, $6)) { YYABORT; } } }
	;

st
	: OP_ST 'M' '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ST, 0, 0, $4)) { YYABORT; } }
	;

stx
	: OP_STX 'M' '[' number ']' {
		if (bpf_set_curr_instr(scanner, parser, BPF_STX, 0, 0, $4)) { YYABORT; } }
	;

jmp
	: OP_JMP label {
		if (bpf_set_jmp_label(scanner, parser, $2, JKL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JA, 0, 0, 0)) { YYABORT; } }
	;

jeq
	: OP_JEQ '#' number ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JEQ 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $6, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JEQ '%' 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JEQ '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JEQ 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JEQ '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jneq
	: OP_JNEQ '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JNEQ 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JNEQ '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jlt
	: OP_JLT '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JLT 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JLT '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jle
	: OP_JLE '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JLE 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JLE '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jgt
	: OP_JGT '#' number ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JGT 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $6, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGT '%' 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGT '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JGT 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGT '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jge
	: OP_JGE '#' number ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JGE 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $6, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGE '%' 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGE '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JGE 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JGE '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

jset
	: OP_JSET '#' number ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JSET 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $6, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JSET '%' 'x' ',' label ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_jmp_label(scanner, parser, $7, JFL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JSET '#' number ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_JSET 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $4, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_JSET '%' 'x' ',' label {
		if (bpf_set_jmp_label(scanner, parser, $5, JTL)) { YYABORT; }
		if (bpf_set_curr_instr(scanner, parser, BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

add
	: OP_ADD '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_ADD | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_ADD 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_ADD '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

sub
	: OP_SUB '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_SUB | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_SUB 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_SUB '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

mul
	: OP_MUL '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MUL | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_MUL 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_MUL '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

div
	: OP_DIV '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_DIV | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_DIV 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_DIV '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

mod
	: OP_MOD '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MOD | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_MOD 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MOD | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_MOD '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_MOD | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

neg
	: OP_NEG {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_NEG, 0, 0, 0)) { YYABORT; } }
	;

and
	: OP_AND '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_AND | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_AND 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_AND | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_AND '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_AND | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

or
	: OP_OR '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_OR | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_OR 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_OR | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_OR '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_OR | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

xor
	: OP_XOR '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_XOR | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_XOR 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_XOR '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

lsh
	: OP_LSH '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_LSH | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_LSH 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_LSH | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_LSH '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_LSH | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

rsh
	: OP_RSH '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_RSH | BPF_K, 0, 0, $3)) { YYABORT; } }
	| OP_RSH 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_RSH | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_RSH '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_ALU | BPF_RSH | BPF_X, 0, 0, 0)) { YYABORT; } }
	;

ret
	: OP_RET 'a' {
		if (bpf_set_curr_instr(scanner, parser, BPF_RET | BPF_A, 0, 0, 0)) { YYABORT; } }
	| OP_RET '%' 'a' {
		if (bpf_set_curr_instr(scanner, parser, BPF_RET | BPF_A, 0, 0, 0)) { YYABORT; } }
	| OP_RET 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_RET | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_RET '%' 'x' {
		if (bpf_set_curr_instr(scanner, parser, BPF_RET | BPF_X, 0, 0, 0)) { YYABORT; } }
	| OP_RET '#' number {
		if (bpf_set_curr_instr(scanner, parser, BPF_RET | BPF_K, 0, 0, $3)) { YYABORT; } }
	;

tax
	: OP_TAX {
		if (bpf_set_curr_instr(scanner, parser, BPF_MISC | BPF_TAX, 0, 0, 0)) { YYABORT; } }
	;

txa
	: OP_TXA {
		if (bpf_set_curr_instr(scanner, parser, BPF_MISC | BPF_TXA, 0, 0, 0)) { YYABORT; } }
	;

%%

static int bpf_assert_max(yyscan_t scanner, yyparse_t parser)
{
	if (parser->curr_instr >= BPF_MAXINSNS) {
		char errbuf[512];
		snprintf(errbuf, sizeof(errbuf), "only max %u insns allowed!", BPF_MAXINSNS);
		yyerror(scanner, parser, errbuf);
		return 1;
	}

	return 0;
}

static int bpf_set_curr_instr(yyscan_t scanner, yyparse_t parser, uint16_t code, uint8_t jt, uint8_t jf,
			       uint32_t k)
{
	if (bpf_assert_max(scanner, parser)) { return 1; }
	parser->out[parser->curr_instr].code = code;
	parser->out[parser->curr_instr].jt = jt;
	parser->out[parser->curr_instr].jf = jf;
	parser->out[parser->curr_instr].k = k;
	parser->curr_instr++;
	return 0;
}

static int bpf_set_curr_label(yyscan_t scanner, yyparse_t parser, char *label)
{
	if (bpf_assert_max(scanner, parser)) { return 1; }
	parser->labels[parser->curr_instr] = label;
	return 0;
}

static int bpf_set_jmp_label(yyscan_t scanner, yyparse_t parser, char *label, enum jmp_type type)
{
	if (bpf_assert_max(scanner, parser)) { return 1; }
	switch (type) {
	case JTL:
		parser->labels_jt[parser->curr_instr] = label;
		break;
	case JFL:
		parser->labels_jf[parser->curr_instr] = label;
		break;
	case JKL:
		parser->labels_k[parser->curr_instr] = label;
		break;
	}

	return 0;
}

static int bpf_find_insns_offset(yyscan_t scanner, yyparse_t parser, const char *label)
{
	int i, max = parser->curr_instr, ret = -ENOENT;

	for (i = 0; i < max; i++) {
		if (parser->labels[i] && !strcmp(label, parser->labels[i])) {
			ret = i;
			break;
		}
	}

	if (ret == -ENOENT) {
		char errbuf[512];
		snprintf(errbuf, sizeof(errbuf), "only max %u insns allowed!", BPF_MAXINSNS);
		yyerror(scanner, parser, errbuf);
		return ret;
	}

	return ret;
}

static int bpf_stage_1_insert_insns(yyscan_t scanner, yyparse_t parser)
{
	return yyparse(scanner, parser);
}

static int bpf_reduce_k_jumps(yyscan_t scanner, yyparse_t parser)
{
	int i;

	for (i = 0; i < parser->curr_instr; i++) {
		if (parser->labels_k[i]) {
			int off = bpf_find_insns_offset(scanner, parser, parser->labels_k[i]);
			if (off < 0) return 1;
			parser->out[i].k = (uint32_t) (off - i - 1);
		}
	}

	return 0;
}

static int bpf_encode_jt_jf_offset(yyscan_t scanner, yyparse_t parser, int off, int i)
{
	int delta = off - i - 1;

	if (delta < 0 || delta > 255) {
		char errbuf[512];
		snprintf(errbuf, sizeof(errbuf), "error: insn #%d jumps to insn #%d, "
				 "which is out of range\n", i, off);
		yyerror(scanner, parser, errbuf);
		return -1;
	}
	return delta;
}

static int bpf_reduce_jt_jumps(yyscan_t scanner, yyparse_t parser)
{
	int i;

	for (i = 0; i < parser->curr_instr; i++) {
		if (parser->labels_jt[i]) {
			int off = bpf_find_insns_offset(scanner, parser, parser->labels_jt[i]);
			if (off < 0) return 1;
			parser->out[i].jt = bpf_encode_jt_jf_offset(scanner, parser, off, i);
		}
	}

	return 0;
}

static int bpf_reduce_jf_jumps(yyscan_t scanner, yyparse_t parser)
{
	int i;

	for (i = 0; i < parser->curr_instr; i++) {
		if (parser->labels_jf[i]) {
			int off = bpf_find_insns_offset(scanner, parser, parser->labels_jf[i]);
			if (off < 0) return 1;
			parser->out[i].jf = bpf_encode_jt_jf_offset(scanner, parser, off, i);
		}
	}

	return 0;
}

static int bpf_stage_2_reduce_labels(yyscan_t scanner, yyparse_t parser)
{
	if (bpf_reduce_k_jumps(scanner, parser)) { return 1; }
	if (bpf_reduce_jt_jumps(scanner, parser)) { return 1; }
	if (bpf_reduce_jf_jumps(scanner, parser)) { return 1; }
	return 0;
}

static void bpf_init(yyparse_t parser)
{
	parser->curr_instr = 0;
	parser->error = NULL;

	parser->out = calloc(BPF_MAXINSNS, sizeof(*parser->out));
	if (!parser->out) { abort(); }
	parser->labels = calloc(BPF_MAXINSNS, sizeof(*parser->labels));
	if (!parser->labels) { abort(); }
	parser->labels_jt = calloc(BPF_MAXINSNS, sizeof(*parser->labels_jt));
	if (!parser->labels_jt) { abort(); }
	parser->labels_jf = calloc(BPF_MAXINSNS, sizeof(*parser->labels_jf));
	if (!parser->labels_jf) { abort(); }
	parser->labels_k = calloc(BPF_MAXINSNS, sizeof(*parser->labels_k));
	if (!parser->labels_k) { abort(); }
}

static void bpf_destroy_labels(yyparse_t parser)
{
	int i;

	for (i = 0; i < parser->curr_instr; i++) {
		free(parser->labels_jf[i]);
		free(parser->labels_jt[i]);
		free(parser->labels_k[i]);
		free(parser->labels[i]);
	}
}

static void bpf_destroy(yyparse_t parser)
{
	bpf_destroy_labels(parser);
	free(parser->out);
	free(parser->labels_jt);
	free(parser->labels_jf);
	free(parser->labels_k);
	free(parser->labels);
	free(parser->error);
}

int bpf_asm_compile(const char *str, int len, struct sock_filter **out, char **error)
{
	int result;
	int err;
	yyscan_t scanner;
	struct yyparse_s parser;

	yylex_init_extra(&parser, &scanner);

	YY_BUFFER_STATE buf = yy_scan_bytes(str, len, scanner);
	yyset_lineno(1, scanner); /* Why doesn't flex initialize this... */

	bpf_init(&parser);
	err = bpf_stage_1_insert_insns(scanner, &parser);
	if (err) {
		*error = parser.error;
		parser.error = NULL;
		result = 0;
		goto out;
	}
	bpf_stage_2_reduce_labels(scanner, &parser);

	*out = parser.out;
	parser.out = NULL;
	result = parser.curr_instr;

out:
	bpf_destroy(&parser);
	yy_delete_buffer(buf, scanner);
	yylex_destroy(scanner);

	return result;
}

void yyerror(yyscan_t scanner, yyparse_t parser, const char *str)
{
	int size = snprintf(NULL, 0, "error: %s at line %d", str, yyget_lineno(scanner));
	parser->error = malloc(size + 1);
	if (!parser->error) { abort(); }
	snprintf(parser->error, size + 1, "error: %s at line %d", str, yyget_lineno(scanner));
}
