// Completed by Guowei Ling

#ifndef CONFIG_H_
#define CONFIG_H_


#include "yacl/base/buffer.h"
#include <cstdint>



void InitializeConfig();

uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start, size_t end);

extern int Ilen;
extern int Imax;
extern int Jlen;
extern int Jmax;
extern uint32_t Cuckoolen;
extern int L1; // 1<< Ilen
extern int L2; // 1<< Ilen
extern int Treelen;
extern int TestNum;
extern uint64_t Mmax;


#endif  // CONFIG_H_
