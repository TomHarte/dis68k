/*	DIS68K by wrm
	Submitted to public domain 10/08/93 (V1.2)
	Current version 1.22, adds "raw" disasm output, ie ready to re-assemble

	1999-11-04:	Add 68030 instructions,
				Add labels.
	2019-03-10:	Remove conio dependency, fix modern C build errors.
	onward: 	see Git history. */


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>


// Enable the #define below to print diagnostics.
//#define PRINT_DIAGNOSTICS

#ifdef PRINT_DIAGNOSTICS
#define diagnostic_printf printf
#else
#define diagnostic_printf(...) while(false);
#endif

struct OpcodeDetails {
	uint16_t and;
	uint16_t xor;
};

const struct OpcodeDetails optab[88] = {
	{0x0000,0x0000}, {0xF1F0,0xC100}, {0xF000,0xD000}, {0xF0C0,0xD0C0},
	{0xFF00,0x0600}, {0xF100,0x5000}, {0xF130,0xD100}, {0xF000,0xC000},
	{0xFF00,0x0200}, {0xF118,0xE100}, {0xFFC0,0xE1C0}, {0xF118,0xE000},
	{0xFFC0,0xE0C0}, {0xF000,0x6000}, {0xF1C0,0x0140}, {0xFFC0,0x0840},
	{0xF1C0,0x0180}, {0xFFC0,0x0880}, {0xF1C0,0x01C0}, {0xFFC0,0x08C0},
	{0xF1C0,0x0100}, {0xFFC0,0x0800}, {0xF1C0,0x4180}, {0xFF00,0x4200},
	{0xF100,0xB000}, {0xF0C0,0xB0C0}, {0xFF00,0x0C00}, {0xF138,0xB108},
	{0xF0F8,0x50C8}, {0xF1C0,0x81C0}, {0xF1C0,0x80C0}, {0xF100,0xB100},
	{0xFF00,0x0A00}, {0xF100,0xC100}, {0xFFB8,0x4880}, {0xFFC0,0x4EC0},
	{0xFFC0,0x4E80}, {0xF1C0,0x41C0}, {0xFFF8,0x4E50}, {0xF118,0xE108},
	{0xFFC0,0xE3C0}, {0xF118,0xE008}, {0xFFC0,0xE2C0}, {0xC000,0x0000},
	{0xFFC0,0x44C0}, {0xFFC0,0x46C0}, {0xFFC0,0x40C0}, {0xFFF0,0x4E60},
	{0xC1C0,0x0040}, {0xFB80,0x4880}, {0xF138,0x0108}, {0xF100,0x7000},
	{0xF1C0,0xC1C0}, {0xF1C0,0xC0C0}, {0xFFC0,0x4800}, {0xFF00,0x4400},
	{0xFF00,0x4000}, {0xFFFF,0x4E71}, {0xFF00,0x4600}, {0xF000,0x8000},
	{0xFF00,0x0000}, {0xFFC0,0x4840}, {0xFFFF,0x4E70}, {0xF118,0xE118},
	{0xFFC0,0xE7C0}, {0xF118,0xE018}, {0xFFC0,0xE6C0}, {0xF118,0xE110},
	{0xFFC0,0xE5C0}, {0xF118,0xE010}, {0xFFC0,0xE4C0}, {0xFFFF,0x4E73},
	{0xFFFF,0x4E77}, {0xFFFF,0x4E75}, {0xF1F0,0x8100}, {0xF0C0,0x50C0},
	{0xFFFF,0x4E72}, {0xF000,0x9000}, {0xF0C0,0x90C0}, {0xFF00,0x0400},
	{0xF100,0x5100}, {0xF130,0x9100}, {0xFFF8,0x4840}, {0xFFC0,0x4AC0},
	{0xFFF0,0x4E40}, {0xFFFF,0x4E76}, {0xFF00,0x4A00}, {0xFFF8,0x4E58}
};

uint32_t address, romstart;
bool rawmode = false;

struct MapEntry {
	uint32_t start;
	uint32_t end;
	enum Type {
		End,
		Data,
		Code
	} type;
} *map = NULL;

const char bra_tab[][4] = {
	"BRA",	"BSR",	"BHI",	"BLS",
	"BCC",	"BCS",	"BNE",	"BEQ",
	"BVC",	"BVS",	"BPL",	"BMI",
	"BGE",	"BLT",	"BGT",	"BLE"
};
const char scc_tab[][4] = {
	"ST",	"SF",	"SHI",	"SLS",
	"SCC",	"SCS",	"SNE",	"SEQ",
	"SVC",	"SVS",	"SPL",	"SMI",
	"SGE",	"SLT",	"SGT",	"SLE"
};
const char size_arr[3] = {'B','W','L'};

/*!
	Reads from @c filename and populates the global variable @c map.
	If @c filename is @c NULL, populates @c map with the empty map.

	@returns @c false if a filename is specified but could not be opened
		or else could not properly be parsed. @c true otherwise.
*/
bool readmap(const char *filename) {
	FILE *fmap;

	// Create a sixteen-item map, to be getting on with.
	size_t allocated_map_size = 16;
	map = (struct MapEntry *)malloc(sizeof(struct MapEntry) * allocated_map_size);

	if (!filename || !(fmap = fopen(filename, "rt"))) {
		if (filename) {
			fprintf(stderr, "Couldn't open %s as a map file\n", filename);
			return false;
		}

		romstart = 0;
		map[0].start = 0L;
		map[0].end = 0xffffffff;
		map[0].type = Code;
		map[1].type = End;
	} else {
		if (!fscanf(fmap,"romstart = %X", &romstart)) {
			fprintf(stderr, "Error in romstart = line!\n");
			return false;
		}

		size_t index = 0;

		while (true) {
			uint32_t start, end;
			char type[10];

			const int items_read = fscanf(fmap, "%x,%x,%9s", &start, &end, type);
			if (items_read == 3) {
				if (index+1 >= allocated_map_size) {
					// Default to 16 entries when first creating a map, double each time the existing
					// estimate isn't enough for both this entry and the terminator yet to come.
					const size_t new_map_size = allocated_map_size ? (allocated_map_size * 2) : 16;
					map = realloc(map, sizeof(struct MapEntry) * new_map_size);
					allocated_map_size = new_map_size;
					if (!map) {
						fprintf(stderr, "Couldn't allocate enough space for map\n");
						return false;
					}
				}

				map[index].start = start;
				map[index].end = end;
				map[index].type = End;
				if(strcmp(type,"data")==0) map[index].type = Data;
				if(strcmp(type,"code")==0) map[index].type = Code;

				if (map[index].type == End) {
					fprintf(stderr, "Couldn't parse type in map file at line %lu ('code' or 'data' misspelt)\n", index+2);
					return false;
				}
				++ index;
			} else {
				if(items_read > 0) {
					fprintf(stderr, "Syntax error on line %lu (%d)\n", index+2, items_read);
					return false;
				}
				break;	// i.e. feof.
			}
		}

		map[index].type = End;
		fclose(fmap);
	}

	return true;
}

/*!
	Gets and echoes the next byte from stdin and increments the global @c address;
	if stdin is exhausted, prints an error and causes the program to exit with
	code EXIT_FAILURE.
*/
unsigned int getbyte() {
	const int byte = fgetc(stdin);
	if (feof(stdin)) {
		fprintf(stderr, "Unexpected end of input\n");
		exit(EXIT_FAILURE);
	}
	++ address;
	printf("%02x ", byte);
	return byte;
}

/*!
	Gets and echoes the next word from stdin and increments the global @c address twice;
	if stdin is exhausted, prints an error and causes the program to exit with
	code EXIT_FAILURE.
*/
int getword() {
	int word = fgetc(stdin) << 8;
	word |= fgetc(stdin);

	if (feof(stdin)) {
		fprintf(stderr, "Unexpected end of input\n");
		exit(EXIT_FAILURE);
	}

	address += 2;
	if (!rawmode) {
		printf("%04x ", word);
	}
	return word;
}

/*!
	Prints the addressing mode @c mode, using @c reg and @c size, to @c out_s.

	@param mode 0 to 12, indicating addressing mode.
	@param size 0 = byte, 1 = word, 2 = long.
*/
void sprintmode(unsigned int mode, unsigned int reg, unsigned int size, char *out_s) {
	const char ir[2] = {'W','L'}; /* for mode 6 */

	switch(mode) {
		case 0  : sprintf(out_s, "D%i", reg);		break;
		case 1  : sprintf(out_s, "A%i", reg);		break;
		case 2  : sprintf(out_s, "(A%i)", reg);		break;
		case 3  : sprintf(out_s, "(A%i)+", reg);	break;
		case 4  : sprintf(out_s, "-(A%i)", reg);	break;
		case 5  : /* reg + disp */
		case 9  : { /* pcr + disp */
			int32_t displacement = (int32_t) getword();
			if (displacement >= 32768) displacement -= 65536;
			if (mode == 5) {
				sprintf(out_s, "%+i(A%i)", displacement, reg);
			} else {
				const uint32_t ldata = address - 2 + displacement;
				if (!rawmode) {
					sprintf(out_s, "%+i(PC) {$%08x}", displacement, ldata);
				} else {
					sprintf(out_s, "%+i(PC)", displacement);
				}
			}
		} break;
		case 6  : /* Areg with index + disp */
		case 10 : {/* PC with index + disp */
			const int data = getword(); /* index and displacement data */

			int displacement = (data & 0x00FF);
			if (displacement >= 128) displacement -= 256;

			const int ireg = (data & 0x7000) >> 12;
			const int itype = (data & 0x8000); /* == 0 is Dreg */
			const int isize = (data & 0x0800) >> 11; /* == 0 is .W else .L */

			if (mode == 6) {
				if (itype == 0) {
					sprintf(out_s, "%+i(A%i,D%i.%c)", displacement, reg, ireg, ir[isize]);
				} else {
					sprintf(out_s, "%+i(A%i,A%i.%c)", displacement, reg, ireg, ir[isize]);
				}
			} else { /* PC */
				if (itype == 0) {
					sprintf(out_s, "%+i(PC,D%i.%c)", displacement, ireg, ir[isize]);
				} else {
					sprintf(out_s, "%+i(PC,A%i.%c)", displacement, ireg, ir[isize]);
				}
			}
		} break;
		case 7  :
			sprintf(out_s, "$0000%04x", getword());
			break;
		case 8  : {
			const int data1 = getword();
			const int data2 = getword();
			sprintf(out_s, "$%04x%04x", data1, data2);
		} break;
		case 11 : {
			const int data1 = getword();
			switch(size) {
				case 0 : sprintf(out_s, "#$%02x", (data1 & 0x00FF));
					break;
				case 1 : sprintf(out_s, "#$%04x", data1);
					break;
				case 2 : {
					const int data2 = getword();
					sprintf(out_s, "#$%04x%04x", data1, data2);
				} break;
			}
		} break;
		default : sprintf(out_s, "?"); fprintf(stderr, "Mode out of range in sprintmode = %i\n", mode);
			break;
	}
}

/*!
	Decodes the addressing mode from @c instruction.

	@returns A mode in the range 0 to 11, if a valid addressing mode could be
		determined; 12 otherwise.
*/
int getmode(int instruction) {
	const int mode = (instruction & 0x0038) >> 3;
	const int reg = instruction & 0x0007;

	if (mode == 7) {
		if (reg >= 5) {
			return 12; /* i.e. invalid */
		} else {
			return 7 + reg;
		}
	}
	return mode;
}

void disasm(unsigned long int start, unsigned long int end) {
	address = start;
	if (address < romstart) {
		printf("Address < RomStart in disasm()!\n");
		exit(1);
	}

	while (!feof(stdin) && (address < end)) {
		if (!rawmode) {
			printf("%08x : ", address);
		} else {
			printf("        ");
		}
		const uint32_t start_address = address;
		const int word = getword();
		bool decoded = false;

		char opcode_s[50], operand_s[101];
		for (int opnum = 1; opnum <= 87; ++opnum) {
			if ((word & optab[opnum].and) == optab[opnum].xor) {
				/* Diagnostic code */
				diagnostic_printf("(%i) ",opnum);

				switch(opnum) { /* opnum = 1..85 */
					case 1  :
					case 74 : { /* ABCD + SBCD */
						const int sreg = word & 0x0007;
						const int dreg = (word & 0x0E00) >> 9;
						if (opnum == 1) {
							sprintf(opcode_s, "ABCD");
						} else {
							sprintf(opcode_s, "SBCD");
						}
						if ((word & 0x0008) == 0) {
							/* reg-reg */
							sprintf(operand_s, "D%i,D%i", sreg, dreg);
						} else {
							/* mem-mem */
							sprintf(operand_s, "-(A%i),-A(%i)", sreg, dreg);
						}
						decoded = true;
					} break;
					case 2  :
					case 7  :
					case 31 :
					case 59 : /* ADD, AND, EOR, OR */
					case 77 : { /* SUB */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;

						/* Diagnostic code */
						diagnostic_printf("dmode = %i, dreg = %i, size = %i",dmode,dreg,size);

						if (size == 3) break;
						/*
						if (dmode == 1) break;
						*/
						if ((opnum ==  2) && (dmode == 1) && (size == 0)) break;
						if ((opnum == 77) && (dmode == 1) && (size == 0)) break;

						const int dir = (word & 0x0100) >> 8; /* 0 = dreg dest */
						if ((opnum == 31) && (dir == 0)) break;
						/* dir == 1 : Dreg is source */
						if ((dir == 1) && (dmode >= 9)) break;

						switch(opnum) {
							case  2 : sprintf(opcode_s, "ADD.%c", size_arr[size]);
								break;
							case  7 : sprintf(opcode_s,"AND.%c", size_arr[size]);
								break;
							case 31 : sprintf(opcode_s, "EOR.%c", size_arr[size]);
								break;
							case 59 : sprintf(opcode_s, "OR.%c", size_arr[size]);
								break;
							case 77 : sprintf(opcode_s, "SUB.%c", size_arr[size]);
								break;
						}

						char dest_s[50];
						sprintmode(dmode, dreg, size, dest_s);

						const int sreg = (word & 0x0E00) >> 9;
						char source_s[50];
						sprintf(source_s, "D%i", sreg);
						/* reverse source & dest if dir == 0 */
						if (dir != 0) {
							sprintf(operand_s, "%s,%s", source_s, dest_s);
						} else {
							sprintf(operand_s, "%s,%s", dest_s, source_s);
						}
						decoded = true;
					} break;
					case 3  :
					case 78 : { /* ADDA + SUBA */
						const int smode = getmode(word);
						const int sreg = word & 0x0007;
						const int dreg = (word & 0x0E00) >> 9;
						const int size = ((word & 0x0100) >> 8) + 1;
						switch(opnum) {
							case  3 : sprintf(opcode_s, "ADDA.%c", size_arr[size]);
								break;
							case 78 : sprintf(opcode_s, "SUBA.%c", size_arr[size]);
								break;
						}
						char source_s[50];
						sprintmode(smode, sreg, size, source_s);
						sprintf(operand_s, "%s,A%i", source_s, sreg);
						decoded = true;
					} break;
					case 4  :
					case 8  :
					case 26 :
					case 32 :
					case 60 :
					case 79 : { /* ADDI, ANDI, CMPI, EORI, ORI, SUBI */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;

						if (size == 3) break;
						if (dmode == 1) break;
						if ((dmode == 9) || (dmode == 10)) break; /* Invalid */
						if (dmode == 12) break;
						if ((dmode == 11) && /* ADDI, CMPI, SUBI */
							((opnum == 4) || (opnum == 26) || (opnum == 79))) break;

						switch(opnum) {
							case  4 : sprintf(opcode_s, "ADDI.%c", size_arr[size]);
								break;
							case  8 : sprintf(opcode_s, "ANDI.%c", size_arr[size]);
								break;
							case 26 : sprintf(opcode_s, "CMPI.%c", size_arr[size]);
								break;
							case 32 : sprintf(opcode_s, "EORI.%c", size_arr[size]);
								break;
							case 60 : sprintf(opcode_s, "ORI.%c", size_arr[size]);
								break;
							case 79 : sprintf(opcode_s, "SUBI.%c", size_arr[size]);
								break;
						}

						const int data = getword();
						char source_s[50];
						switch(size) {
							case 0 : sprintf(source_s, "#$%02X", (data & 0x00FF));
								break;
							case 1 : sprintf(source_s, "#$%04X", data);
								break;
							case 2 :
								sprintf(source_s, "#$%04X%04X", data, getword());
								break;
						}

						char dest_s[50];
						if (dmode == 11) {
							sprintf(dest_s, "SR");
						} else {
							sprintmode(dmode, dreg, size, dest_s);
						}
						sprintf(operand_s, "%s,%s", source_s, dest_s);
						decoded = true;
					} break;
					case 5  :
					case 80 : {/* ADDQ + SUBQ */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;

						if (size == 3) break;
						if (dmode >= 9) break;
						if ((size == 0) && (dmode == 1)) break;

						if (opnum == 5) {
							sprintf(opcode_s,"ADDQ.%c",size_arr[size]);
						} else {
							sprintf(opcode_s,"SUBQ.%c",size_arr[size]);
						}
						char dest_s[50];
						sprintmode(dmode, dreg, size, dest_s);
						const int count = (word & 0x0E00) >> 9;
						sprintf(operand_s, "#%i,%s", count ? count : 8, dest_s);
						decoded = true;
					} break;
					case 6  :
					case 81 : /* ADDX + SUBX */
					case 27 : { /* CMPM */
						const int size = (word & 0x00C0) >> 6;
						if (size == 3) break;

						const int sreg = word & 0x0007;
						const int dreg = (word & 0x0E00) >> 9;
						switch(opnum) {
							case 6  : sprintf(opcode_s, "ADDX.%c", size_arr[size]);
								break;
							case 81 : sprintf(opcode_s, "SUBX.%c", size_arr[size]);
								break;
							case 27 : sprintf(opcode_s, "CMPM.%c", size_arr[size]);
								break;
						}
						if ((opnum != 27) && ((word & 0x0008) == 0)) {
							/* reg-reg */
							sprintf(operand_s,"D%i,D%i",sreg,dreg);
						} else {
							/* mem-mem */
							sprintf(operand_s,"-(A%i),-(A%i)",sreg,dreg);
						}
						if (opnum == 27) {
							sprintf(operand_s,"(A%i)+,(A%i)+",sreg,dreg);
						}
						decoded = true;
					} break;
					case 9  :
					case 11 :
					case 39 :
					case 41 :
					case 63 :
					case 65 :
					case 67 :
					case 69 : { /* ASL, ASR, LSL, LSR, ROL, ROR, ROXL, ROXR */
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;
						if (size == 3) break;

						switch(opnum) {
							case 9  : sprintf(opcode_s, "ASL.%c", size_arr[size]);
								break;
							case 11 : sprintf(opcode_s, "ASR.%c", size_arr[size]);
								break;
							case 39 : sprintf(opcode_s, "LSL.%c", size_arr[size]);
								break;
							case 41 : sprintf(opcode_s, "LSR.%c", size_arr[size]);
								break;
							case 63 : sprintf(opcode_s, "ROL.%c", size_arr[size]);
								break;
							case 65 : sprintf(opcode_s, "ROR.%c", size_arr[size]);
								break;
							case 67 : sprintf(opcode_s, "ROXL.%c", size_arr[size]);
								break;
							case 69 : sprintf(opcode_s, "ROXR.%c", size_arr[size]);
								break;
						}
						int count = (word & 0x0E00) >> 9;
						if (((word & 0x0020) >> 5) == 0) { /* imm */
							if (count == 0) count = 8;
							sprintf(operand_s, "#%i,D%i", count, (word & 0x0007));
						} else { /* count in dreg */
							sprintf(operand_s, "D%i,D%i", count, (word & 0x0007));
						}
						decoded = true;
					} break;
					case 10 :
					case 12 :
					case 40 :
					case 42 :
					case 64 :
					case 66 :
					case 68 : /* Memory-to-memory */
					case 70 : { /* ASL, ASR, LSL, LSR, ROL, ROR, ROXL, ROXR */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						if ((dmode <= 1) || (dmode >= 9)) break; /* Invalid */

						switch(opnum) {
							case 10 : sprintf(opcode_s,"ASL");
								break;
							case 12 : sprintf(opcode_s,"ASR");
								break;
							case 40 : sprintf(opcode_s,"LSL");
								break;
							case 42 : sprintf(opcode_s,"LSR");
								break;
							case 64 : sprintf(opcode_s,"ROL");
								break;
							case 66 : sprintf(opcode_s,"ROR");
								break;
							case 68 : sprintf(opcode_s,"ROXL");
								break;
							case 70 : sprintf(opcode_s,"ROXR");
								break;
						}
						sprintmode(dmode, dreg, 0, operand_s);
						decoded = true;
					} break;
					case 13 : {/* Bcc */
						const int cc = (word & 0x0F00) >> 8;
						sprintf(opcode_s, "%s", bra_tab[cc]);

						int offset = (word & 0x00FF);
						if (offset != 0) {
							if (offset >= 128) offset -= 256;
							if (!rawmode) {
								sprintf(operand_s, "$%08x", address + offset);
							} else {
								sprintf(operand_s, "*%+d", offset);
							}
						} else {
							offset = getword();
							if (offset >= 32768l) offset -= 65536l;
							if (!rawmode) {
								sprintf(operand_s, "$%08x" , address - 2 + offset);
							} else {
								sprintf(operand_s, "*%+d", offset);
							}
						}
						decoded = true;
					} break;
					case 14 :
					case 15 :
					case 16 :
					case 17 : /* BCHG + BCLR */
					case 18 :
					case 19 : /* BSET */
					case 20 :
					case 21 : {/* BTST */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;

						if (dmode == 1) break;
						if (dmode >= 11) break;
						if ((opnum < 20) && (dmode >= 9)) break;

						const int sreg = (word & 0x0E00) >> 9;
						char source_s[50];
						switch(opnum) {
							case 14 : /* BCHG_DREG */
								sprintf(opcode_s, "BCHG");
								sprintf(source_s, "D%i", sreg);
								break;
							case 15 : {/* BCHG_IMM */
								sprintf(opcode_s, "BCHG");
								const int data = getword() & 0x002F;
								sprintf(source_s, "#%i", data);
							} break;
							case 16 : /* BCLR_DREG */
								sprintf(opcode_s, "BCLR");
								sprintf(source_s, "D%i", sreg);
								break;
							case 17 : {/* BCLR_IMM */
								sprintf(opcode_s, "BCLR");
								const int data = getword() & 0x002F;
								sprintf(source_s, "#%i", data);
							} break;
							case 18 : /* BSET_DREG */
								sprintf(opcode_s, "BSET");
								sprintf(source_s, "D%i", sreg);
								break;
							case 19 : { /* BSET_IMM */
								sprintf(opcode_s, "BSET");
								const int data = getword() & 0x002F;
								sprintf(source_s, "#%i", data);
							} break;
							case 20 : /* BTST_DREG */
								sprintf(opcode_s,"BTST");
								sprintf(source_s, "D%i", sreg);
								break;
							case 21 : {/* BTST_IMM */
								sprintf(opcode_s,"BTST");
								const int data = getword() & 0x002F;
								sprintf(source_s, "#%i", data);
							} break;
						}
						char dest_s[50];
						sprintmode(dmode, dreg, 0, dest_s);
						sprintf(operand_s, "%s,%s", source_s, dest_s);
						decoded = true;
					} break;
					case 22 : /* CHK */
					case 29 :
					case 30 :
					case 52 :
					case 53 : /* DIVS, DIVU, MULS, MULU */
					case 24 : {/* CMP */
						const int smode = getmode(word);
						if ((smode == 1) && (opnum != 24)) break;
						if (smode >= 12) break;

						const int sreg = word & 0x0007;
						const int dreg = (word & 0x0E00) >> 9;

						int size;
						if (opnum == 24) {
							size = (word & 0x00C0) >> 6;
						} else {
							size = 1; /* WORD */
						}
						if (size == 3) break;

						switch(opnum) {
							case 22 : /* CHK */
								sprintf(opcode_s, "CHK");
								break;
							case 24 : /* CMP */
								sprintf(opcode_s, "CMP.%c", size_arr[size]);
								break;
							case 29 : /* DIVS */
								sprintf(opcode_s, "DIVS");
								break;
							case 30 : /* DIVU */
								sprintf(opcode_s, "DIVU");
								break;
							case 52 : /* MULS */
								sprintf(opcode_s, "MULS");
								break;
							case 53 : /* MULU */
								sprintf(opcode_s, "MULU");
								break;
						}
						char source_s[50];
						sprintmode(smode, sreg, size, source_s);
						sprintf(operand_s, "%s,D%i", source_s, dreg);
						decoded = true;
					} break;
					case 23 : {/* CLR */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						if ((dmode == 1) || (dmode >= 9)) break; /* Invalid */

						const int size = (word & 0x00C0) >> 6;
						if (size == 3) break;

						sprintf(opcode_s, "CLR.%c", size_arr[size]);
						sprintmode(dmode, dreg, size, operand_s);
						decoded = true;
					} break;
					case 25 : {/* CMPA */
						const int smode = getmode(word);
						const int sreg = word & 0x0007;
						const int areg = (word & 0x0E00) >> 9;
						const int size = ((word & 0x0100) >> 8) + 1;

						sprintf(opcode_s, "CMPA.%c", size_arr[size]);
						char source_s[50];
						sprintmode(smode, sreg, size, source_s);
						sprintf(operand_s, "%s,A%i", source_s, areg);
						decoded = true;
					} break;
					case 28 : { /* DBcc */
						const int cc = (word & 0x0F00) >> 8;
						sprintf(opcode_s, "D%s", bra_tab[cc]);

						if (cc == 0) sprintf(opcode_s, "DBT");
						if (cc == 1) sprintf(opcode_s, "DBF");
						int offset = getword();
						if (offset >= 32768) offset -= 65536;
						const int dreg = word & 0x0007;
						sprintf(operand_s, "D%i,$%08x", dreg, address - 2 + offset);
						decoded = true;
					} break;
					case 33 : { /* EXG */
						const int dmode = (word & 0x00F8) >> 3;
						/*	8 - Both Dreg
							9 - Both Areg
							17 - Dreg + Areg */
						if ((dmode != 8) && (dmode != 9) && (dmode != 17)) break;

						const int dreg = word & 0x0007;
						const int areg = (word & 0x0E00) >> 9;
						sprintf(opcode_s, "EXG");

						switch(dmode) {
							case 8  : sprintf(operand_s, "D%i,D%i", dreg, areg);
								break;
							case 9  : sprintf(operand_s, "A%i,A%i", dreg, areg);
								break;
							case 17 : sprintf(operand_s, "D%i,A%i", dreg, areg);
								break;
						}
						decoded = true;
					} break;
					case 34 : {/* EXT */
						const int dreg = word & 0x0007;
						const int size = ((word & 0x0040) >> 6) + 1;
						sprintf(opcode_s, "EXT.%c", size_arr[size]);
						sprintf(operand_s, "D%i", dreg);
						decoded = true;
					} break;
					case 35 :
					case 36 : {/* JMP + JSR */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;

						if (dmode <= 1) break;
						if ((dmode == 3) || (dmode == 4)) break;
						if (dmode >= 11) break; /* Invalid */

						switch(opnum) {
							case 35 : sprintf(opcode_s, "JMP");
								break;
							case 36 : sprintf(opcode_s, "JSR");
								break;
						}

						sprintmode(dmode, dreg, 0, operand_s);
						decoded = true;
					} break;
					case 37 : {/* LEA */
						const int smode = getmode(word);
						if ((smode == 0) || (smode == 1)) break;
						if ((smode == 3) || (smode == 4)) break;
						if (smode >= 11) break;

						const int sreg = word & 0x0007;
						sprintf(opcode_s, "LEA");
						char source_s[50];
						sprintmode(smode, sreg, 0, source_s);

						const int dreg = (word & 0x0E00) >> 9;
						sprintf(operand_s, "%s,A%i", source_s, dreg);
						decoded = true;
					} break;
					case 38 : {/* LINK */
						const int areg = word & 0x0007;
						int offset = getword();
						if (offset >= 32768) offset -= 65536;
						sprintf(opcode_s, "LINK");
						sprintf(operand_s, "A%i,#%+i", areg, offset);
						decoded = true;
					} break;
					case 43 : {/* MOVE */
						const int smode = getmode(word);
						const int data = ((word & 0x0E00) >> 9) | ((word & 0x01C0) >> 3);
						const int dmode = getmode(data);

						const int sreg = word & 0x0007;
						const int dreg = data & 0x0007;

						int size = (word & 0x3000) >> 12; /* 1=B, 2=L, 3=W */
						if (size == 0) break;
						switch(size) {
							case 1 : size = 0;
								break;
							case 2 : size = 2;
								break;
							case 3 : size = 1;
								break;
						}
						/* 0=B, 1=W, 2=L */

						/*
						printf("smode = %i dmode = %i ",smode,dmode);
						printf("sreg = %i dreg = %i \n",sreg,dreg);
						*/

						/* check for illegal modes */
						// smode=1, size=1 is legal; 36 0d
						// if ((smode == 1) && (size == 1)) break;
						// smode=9 is legal; 2d 40 ff ec
						// smode=10 is legal; 30 3b 00 00
						// if ((smode == 9) || (smode == 10)) break;
						if (smode > 11) break;
						if (dmode == 1) break;
						if (dmode >= 9) break;

						sprintf(opcode_s,"MOVE.%c",size_arr[size]);

						char source_s[50], dest_s[50];
						sprintmode(smode, sreg, size, source_s);
						sprintmode(dmode, dreg, size, dest_s);
						sprintf(operand_s, "%s,%s ", source_s, dest_s);
						decoded = true;
					} break;
					case 44 : /* MOVE to CCR */
					case 45 : {/* MOVE to SR */
						const int smode = getmode(word);
						const int sreg = word & 0x0007;
						const int size = 1; /* WORD */

						if (smode == 1) break;
						if (smode >= 12) break;

						sprintf(opcode_s, "MOVE.W");
						char source_s[50];
						sprintmode(smode, sreg, size, source_s);
						if (opnum == 44) {
							sprintf(operand_s, "%s,CCR", source_s);
						} else {
							sprintf(operand_s, "%s,SR", source_s);
						}
						decoded = true;
					} break;
					case 46 : {/* MOVE from SR */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = 1; /* WORD */

						if (dmode == 1) break;
						if (dmode >= 9) break;

						sprintf(opcode_s, "MOVE.W");
						char dest_s[50];
						sprintmode(dmode, dreg, size, dest_s);
						sprintf(operand_s, "SR,%s", dest_s);
						decoded = true;
					} break;
					case 47 : { /* MOVE USP */
						const int sreg = word & 0x0007;
						sprintf(opcode_s, "MOVE");
						if ((word & 0x0008) == 0) {
							/* to USP */
							sprintf(operand_s, "A%i,USP", word & 0x0007);
						} else {
							/* from USP */
							sprintf(operand_s, "USP,A%i", word & 0x0007);
						}
						decoded = true;
					} break;
					case 48 : {/* MOVEA */
						const int smode = getmode(word);
						const int sreg = word & 0x0007;
						int size = (word & 0x3000) >> 12;

						/* 2 = L, 3 = W */
						if (size <= 1) break;
						if (size == 3) size = 1;
						/* 1 = W, 2 = L */

						const int dreg = (word & 0x0e00) >> 9;

						sprintf(opcode_s, "MOVEA.%c", size_arr[size]);

						char source_s[50];
						sprintmode(smode, sreg, size, source_s);
						sprintf(operand_s, "%s,A%i", source_s, dreg);
						decoded = true;
					} break;
					case 49 : {/* MOVEM */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = ((word & 0x0040) >> 6) + 1;

						if ((dmode == 0) || (dmode == 1)) break;
						if (dmode >= 11) break;

						const int dir = (word & 0x0400) >> 10; /* 1 == from mem */
						if ((dir == 0) && (dmode == 3)) break;
						if ((dir == 1) && (dmode == 4)) break;

						const int data = getword();
						if (dmode == 4) { /* dir == 0 if dmode == 4 !! */
							/* reverse bits in data */
							int temp = data;
							int data = 0;
							for (int i = 0; i <= 15; ++i) {
								data = (data >> 1) | (temp & 0x8000);
								temp = temp << 1;
							}
						}

						char source_s[50] = "";
						char dest_s[50] = "";

						/**** DATA LIST ***/

						int rlist[11];
						for (int i = 0 ; i <= 7; ++i) {
							rlist[i + 1] = (data >> i) & 0x0001;
						}
						rlist[0] = 0;
						rlist[9] = 0;
						rlist[10] = 0;

						for (int i = 1; i <= 8 ; ++i) {
							if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
								(rlist[i+1] == 1) && (rlist[i+2] == 1)) {
								/* first reg in list */
								char temp_s[50];
								sprintf(temp_s, "D%i-", i - 1);
								strcat(source_s, temp_s);
							}
							if ((rlist[i] == 1) && (rlist[i+1] == 0)) {
								char temp_s[50];
								sprintf(temp_s, "D%i,", i-1);
								strcat(source_s, temp_s);
							}
							if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
								(rlist[i+1] == 1) && (rlist[i+2] == 0)) {
								char temp_s[50];
								sprintf(temp_s, "D%i,", i-1);
								strcat(source_s, temp_s);
							}
						}

						/**** ADDRESS LIST ***/

						for (int i = 8; i <= 15; ++i) {
							rlist[i - 7] = (data >> i) & 0x0001;
						}
						rlist[0] = 0;
						rlist[9] = 0;
						rlist[10] = 0;

						for (int i = 1; i <= 8; ++i) {
							if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
								(rlist[i+1] == 1) && (rlist[i+2] == 1)) {
								/* first reg in list */
								char temp_s[50];
								sprintf(temp_s, "A%i-", i - 1);
								strcat(source_s, temp_s);
							}
							if ((rlist[i] == 1) && (rlist[i+1] == 0)) {
								char temp_s[50];
								sprintf(temp_s, "A%i,", i - 1);
								strcat(source_s, temp_s);
							}
							if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
								(rlist[i+1] == 1) && (rlist[i+2] == 0)) {
								char temp_s[50];
								sprintf(temp_s,"A%i,", i - 1);
								strcat(source_s, temp_s);
							}
						}

						sprintf(opcode_s, "MOVEM.%c", size_arr[size]);
						sprintmode(dmode, dreg, size, dest_s);
						if (dir == 0) {
							/* the comma comes from the reglist */
							sprintf(operand_s, "%s%s", source_s, dest_s);
						} else {
							/* add the comma */
							source_s[strlen(source_s)-1] = ' '; /* and remove the other one */
							sprintf(operand_s, "%s,%s", dest_s, source_s);
						}
						decoded = true;
					} break;
					case 50 : {/* MOVEP */
						const int dreg = (word & 0x0E00) >> 9;
						const int areg = word & 0x0007;
						const int size = ((word & 0x0040) >> 6) + 1;

						if (size == 3) break;

						const int data = getword();
						sprintf(opcode_s, "MOVEP.%c", size_arr[size]);
						if ((word & 0x0080) == 0) {
							/* mem -> data reg */
							sprintf(operand_s, "$%04X(A%i),D%i", data, areg, dreg);
						} else {
							/* data reg -> mem */
							sprintf(operand_s, "D%i,$%04X(A%i)", dreg, data, areg);
						}
						decoded = true;
					} break;
					case 51 : { /* MOVEQ */
						const int dreg = (word & 0x0E00) >> 9;
						sprintf(opcode_s, "MOVEQ");
						sprintf(operand_s, "#$%02X,D%i", (word & 0x00FF), dreg);
						decoded = true;
					} break;
					case 54 : /* NBCD */
					case 55 :
					case 56 :
					case 58 : { /* NEG, NEGX + NOT */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;

						if (dmode == 1) break;
						if (dmode >= 9) break;
						if (size == 3) break;

						switch(opnum) {
							case 54 : sprintf(opcode_s, "NBCD.%c", size_arr[size]);
								break;
							case 55 : sprintf(opcode_s, "NEG.%c", size_arr[size]);
								break;
							case 56 : sprintf(opcode_s, "NEGX.%c", size_arr[size]);
								break;
							case 58 : sprintf(opcode_s, "NOT.%c", size_arr[size]);
								break;
						}
						sprintmode(dmode, dreg, size, operand_s);
						decoded = true;
					} break;
					case 57 :
					case 62 :
					case 71 :
					case 72 :
					case 73 :
					case 76 :
					case 85 : { /* NOP, RESET, RTE, RTR, RTS, STOP, TRAPV */
						switch(opnum) {
							case 57 : sprintf(opcode_s, "NOP");
								sprintf(operand_s, " ");
								break;
							case 62 : sprintf(opcode_s, "RESET");
								sprintf(operand_s, " ");
								break;
							case 71 : sprintf(opcode_s, "RTE");
								sprintf(operand_s, " ");
								break;
							case 72 : sprintf(opcode_s, "RTR");
								sprintf(operand_s, " ");
								break;
							case 73 : sprintf(opcode_s, "RTS");
								sprintf(operand_s, " ");
								break;
							case 76 : sprintf(opcode_s, "STOP");
								sprintf(operand_s, " ");
								break;
							case 85 : sprintf(opcode_s, "TRAPV");
								sprintf(operand_s, " ");
								break;
						}
						decoded = true;
					} break;
					case 61 : { /* PEA */
						const int smode = getmode(word);
						if (smode <= 1) break;
						if ((smode == 3) || (smode == 4)) break;
						if (smode >= 11) break;

						sprintf(opcode_s, "PEA");
						const int sreg = word & 0x0007;
						sprintmode(smode, sreg, 0, operand_s);
						decoded = true;
					} break;
					case 75 : {/* Scc */
						const int dmode = getmode(word);
						if (dmode == 1) break;
						if (dmode >= 9) break;

						const int dreg = word & 0x0007;
						const int cc = (word & 0x0F00) >> 8;

						sprintf(opcode_s, "%s", scc_tab[cc]);
						char dest_s[50];
						sprintmode(dmode, dreg, 0, dest_s);
						sprintf(operand_s, "%s", dest_s);
						decoded = true;
					} break;
					case 82 : {/* SWAP */
						const int dreg = word & 0x0007;
						sprintf(opcode_s, "SWAP");
						sprintf(operand_s, "D%i", dreg);
						decoded = true;
					} break;
					case 83 : { /* TAS */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						if (dmode == 1) break;
						if (dmode >= 9) break;

						sprintf(opcode_s, "TAS ");
						sprintmode(dmode, dreg, 0, operand_s);
						decoded = true;
					} break;
					case 84 : { /* TRAP */
						const int dreg = word & 0x000F;
						sprintf(opcode_s, "TRAP");
						sprintf(operand_s, "%i", dreg);
						decoded = true;
					} break;
					case 86 : { /* TST */
						const int dmode = getmode(word);
						const int dreg = word & 0x0007;
						const int size = (word & 0x00C0) >> 6;

						if (dmode == 1) break;
						if (dmode >= 9) break;
						if (size == 3) break;

						sprintf(opcode_s, "TST ");
						sprintmode(dmode, dreg, size, operand_s);
						decoded = true;
					} break;
					case 87 : {/* UNLK */
						const int areg = word & 0x0007;
						sprintf(opcode_s, "UNLK");
						sprintf(operand_s, "A%i", areg);
						decoded = true;
					} break;

					default : printf("opnum out of range in switch (=%i)\n", opnum);
						exit(1);
				}
			}
			if (decoded) opnum = 88;
		}

		const int fetched = address - start_address;
		if (!rawmode) {
			for (int i = 0 ; i < (5 - fetched); ++i) printf("     ");
		}
		if (decoded != 0) {
			printf("%-8s %s\n", opcode_s, operand_s);
		} else {
			printf("???\n");
		}
	}
}

/*!
	Consumes end - start input bytes and outputs them as a data segment;
	at exit the global @c address is equal to @c end.

	Any bytes that are within the printable character range are output as
	those characters; full stops fill in for unprintable characters.
*/
void datadump(uint32_t start, uint32_t end) {
	address = start;
	if (address < romstart) {
		fprintf(stderr, "Address < RomStart in datadump()!\n");
		exit(EXIT_FAILURE);
	}

	while (!feof(stdin) && (address < end)) {
		printf("%08x : ", address);

		const uint32_t reamaining_bytes = end - address;
		const int  bytes_to_print = (reamaining_bytes > 16) ? 16 : reamaining_bytes;

		int toprint[16] ;
		for (int i = 0; i < 16; ++i) {
			if (i >= bytes_to_print)
				printf("   ");
			else
				toprint[i] = getbyte();
		}
		printf("  ");
		for (int i = 0; i < 16; ++i) {
			const int byte = toprint[i];
			if (i >= bytes_to_print)
				printf(" ");
			else if (isprint(byte))
				printf("%c", byte);
			else
				printf(".");
		}
		fputc('\n', stdout);
	}
}

int main(int argc, char *argv[]) {
	char *mapfilename = NULL;
	int argument = 1;
	while(argument < argc) {
		// Output plain help?
		if(!strcmp(argv[argument], "-h") || !strcmp(argv[argument], "--help")) {
			printf("Usage: %s [-m mapfile] [-r]\n", argv[0]);
			printf("Reads a binary file from stdin; prints disassembly to stdout.\n");
			printf("If a mapfile is specified, it can be used to demark code and data segments.\n");
			printf("-r disables output of addresses when disassembling.\n");
			printf("Or use -v for version history.\n\n");
			printf("Map files should have as their first line:\n");
			printf("romstart = x\n");
			printf("... indicating a starting address in hexadecimal. From there put lines of the form:\n");
			printf("<start>,<end>,[code/data]\n");
			printf("... to demark sections of code or data. The start and end addresses should be in hexadecimal.\n");
			return EXIT_SUCCESS;
		}

		// Output version history?
		if(!strcmp(argv[argument], "-v")) {
			printf("Revision list : 1.0  13/02/91\n");
			printf("                1.1  05/03/91 : Reglist upgraded.\n");
			printf("                                .MAP file added.\n");
			printf("                                .MSK file removed.\n");
			printf("                1.11 24/04/91 : MOVEA bug fixed.\n");
			printf("                1.12 24/12/92 : SUB bug fixed.\n");
			printf("                                EXG/AND.W book bug fixed.\n");
			printf("                1.2  10/08/93 : Submitted to public domain.\n");
			printf("                1.21 07/07/94 : Added 'raw' output mode.\n");
			printf("                2019 onwards  : See Git commit history.\n");
			return EXIT_SUCCESS;
		}

		if(!strcmp(argv[argument], "-r")) {
			rawmode = true;
			++ argument;
			continue;
		}

		if(!strcmp(argv[argument], "-m") && argument+1 != argc) {
			mapfilename = argv[argument+1];
			argument += 2;
			continue;
		}

		fprintf(stderr, "Unrecognised option: %s", argv[argument]);
		return EXIT_FAILURE;
	}

	if (!readmap(mapfilename)) {
		return EXIT_FAILURE;
	}

	size_t index = 0;
	while (map[index].type != End) {
		printf(index ? "\n" : "");
		if (map[index].type == Data) datadump(map[index].start, map[index].end);
		if (map[index].type == Code) disasm(map[index].start, map[index].end);
		++ index;
	}
	return 0;
}
