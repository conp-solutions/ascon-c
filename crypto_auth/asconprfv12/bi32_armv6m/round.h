#ifndef ROUND_H_
#define ROUND_H_

#include "ascon.h"
#include "constants.h"
#include "forceinline.h"
#include "printstate.h"
#include "word.h"

forceinline void ROUND_LOOP(ascon_state_t* s, const uint8_t* C,
                            const uint8_t* E) {
  uint32_t tmp0, tmp1;
  __asm__ __volatile__(
      "@.syntax_unified\n\t"
      "rbegin_%=:;\n\t"
      "ldrb %[tmp2], [%[tmp1], #0]\n\t"
      "push  {%[tmp0]}\n\t"
      "eor %[x0_l], %[x0_l], %[x4_l]\n\t"
      "eor %[x4_l], %[x4_l], %[x3_l]\n\t"
      "eor %[x2_l], %[x2_l], %[x1_l]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp2]\n\t"
      "ldrb %[tmp2], [%[tmp1], #1]\n\t"
      "add %[tmp1], %[tmp1], #2\n\t"
      "movs %[tmp0], %[x2_h]\n\t"
      "push  {%[tmp1]}\n\t"
      "eor %[tmp0], %[tmp0], %[tmp2]\n\t"
      "movs %[x2_h], %[tmp0]\n\t"
      "movs %[tmp0], %[x0_l]\n\t"
      "bic %[tmp0], %[tmp0], %[x4_l]\n\t"
      "movs %[tmp1], %[x2_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x1_l]\n\t"
      "eor %[x0_l], %[x0_l], %[tmp1]\n\t"
      "movs %[tmp1], %[x4_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x3_l]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp1]\n\t"
      "movs %[tmp2], %[x1_l]\n\t"
      "bic %[tmp2], %[tmp2], %[x0_l]\n\t"
      "eor %[tmp2], %[x4_l], %[tmp2]\n\t"
      "movs %[tmp1], %[x3_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x2_l]\n\t"
      "eor %[tmp1], %[x1_l], %[tmp1]\n\t"
      "eor %[tmp0], %[x3_l], %[tmp0]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x0_l]\n\t"
      "eor %[x0_l], %[x0_l], %[tmp2]\n\t"
      "movs %[x4_l], %[x4_h]\n\t"
      "movs %[x1_l], %[x1_h]\n\t"
      "movs %[x3_l], %[x3_h]\n\t"
      "movs %[x3_h], %[tmp0]\n\t"
      "movs %[x1_h], %[tmp1]\n\t"
      "movs %[tmp0], %[x0_h]\n\t"
      "movs %[tmp1], %[x2_h]\n\t"
      "movs %[x0_h], %[x0_l]\n\t"
      "movs %[x2_h], %[x2_l]\n\t"
      "eor %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[x4_l], %[x4_l], %[x3_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x1_l]\n\t"
      "movs %[x0_l], %[tmp0] \n\t"
      "bic %[x0_l], %[x0_l], %[x4_l]\n\t"
      "movs %[x2_l], %[tmp1] \n\t"
      "bic %[x2_l], %[x2_l], %[x1_l]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "movs %[x2_l], %[x4_l] \n\t"
      "bic %[x2_l], %[x2_l], %[x3_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x2_l]\n\t"
      "movs %[x2_l], %[x1_l]\n\t"
      "bic %[x2_l], %[x2_l], %[tmp0]\n\t"
      "eor %[x4_l], %[x4_l], %[x2_l]\n\t"
      "movs %[x2_l], %[x3_l] \n\t"
      "bic %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[x2_l]\n\t"
      "eor %[x3_l], %[x3_l], %[x0_l]\n\t"
      "eor %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[tmp0]\n\t"
      "eor %[tmp0], %[tmp0], %[x4_l]\n\t"
      "movs %[x4_h], %[tmp1]\n\t"
      "movs %[x2_l], %[x3_h]\n\t"
      "movs %[x3_h], %[x1_l]\n\t"
      "movs %[tmp1], #17\n\t"
      "movs %[x0_l], %[tmp2]\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x0_l], %[tmp2], %[x0_l]\n\t"
      "movs %[x1_l], %[x4_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x4_l], %[x1_l]\n\t"
      "movs %[tmp1], #3\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[tmp2], %[tmp2], %[x1_l]\n\t"
      "movs %[tmp1], #4\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x4_l], %[x4_l], %[x0_l]\n\t"
      "movs %[x1_l], %[x2_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x3_l], %[x1_l]\n\t"
      "movs %[tmp1], #3\n\t"
      "movs %[x0_l], %[x3_l]\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x0_l], %[x2_l], %[x0_l]\n\t"
      "movs %[tmp1], #5\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x2_l], %[x0_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x3_l], %[x3_l], %[x1_l]\n\t"
      "movs %[x0_l], %[x0_h]\n\t"
      "movs %[x1_l], %[x1_h]\n\t"
      "movs %[x1_h], %[x2_l]\n\t"
      "movs %[x0_h], %[tmp2]\n\t"
      "movs %[tmp2], %[x4_h]\n\t"
      "movs %[x4_h], %[x4_l]\n\t"
      "movs %[x4_l], %[x3_h]\n\t"
      "movs %[x3_h], %[x3_l]\n\t"
      "movs %[x3_l], %[x0_l]\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x3_l], %[tmp0], %[x3_l]\n\t"
      "movs %[tmp1], #4\n\t"
      "movs %[x2_l], %[tmp0]\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x0_l], %[x2_l]\n\t"
      "movs %[tmp1], #9\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x0_l], %[x0_l], %[x3_l]\n\t"
      "movs %[tmp1], #10\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "movs %[tmp1], #11\n\t"
      "movs %[x2_l], %[x1_l]\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x1_l], %[x2_l]\n\t"
      "movs %[x3_l], %[x4_l]\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x3_l], %[x4_l], %[x3_l]\n\t"
      "movs %[tmp1], #19\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[x3_l]\n\t"
      "movs %[tmp1], #20\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x4_l], %[x4_l], %[x2_l]\n\t"
      "movs %[x2_l], %[x2_h]\n\t"
      "movs %[x3_l], %[x1_h]\n\t"
      "movs %[x1_h], %[x4_l]\n\t"
      "movs %[x2_h], %[tmp0]\n\t"
      "movs %[x4_l], #2\n\t"
      "mvn %[tmp0], %[tmp2]\n\t"
      "ror %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[tmp0], %[x2_l], %[tmp0]\n\t"
      "movs %[x4_l], #3\n\t"
      "mvn %[tmp1], %[x2_l]\n\t"
      "ror %[tmp1], %[tmp1], %[x4_l]\n\t"
      "eor %[tmp1], %[tmp2], %[tmp1]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp1]\n\t"
      "movs %[x4_l], #1\n\t"
      "pop  {%[tmp1]}\n\t"
      "ror %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[tmp2], %[tmp2], %[tmp0]\n\t"
      "pop  {%[tmp0]}\n\t"
      "movs %[x4_l], %[x0_h]\n\t"
      "movs %[x0_h], %[x2_h]\n\t"
      "movs %[x2_h], %[tmp2]\n\t"
      "cmp %[tmp1], %[tmp0]\n\t"
      "beq rend_%=\n\t"
      "b rbegin_%=\n\t"
      "rend_%=:;\n\t"
      :
      [x0_l] "+l"(s->w[0][0]), [x0_h] "+r"(s->w[0][1]), [x1_l] "+l"(s->w[1][0]),
      [x1_h] "+r"(s->w[1][1]), [x2_l] "+l"(s->w[2][0]), [x2_h] "+r"(s->w[2][1]),
      [x3_l] "+l"(s->w[3][0]), [x3_h] "+r"(s->w[3][1]), [x4_l] "+l"(s->w[4][0]),
      [x4_h] "+r"(s->w[4][1]), [tmp1] "+l"(C), [tmp0] "+l"(E), [tmp2] "=l"(tmp1)
      :
      :);
  printstate(" round output", s);
}

forceinline void ROUND(ascon_state_t* s, uint64_t C) {
  uint32_t tmp0, tmp1, tmp2;
  __asm__ __volatile__(
      "@.syntax_unified\n\t"
      "movs %[tmp1], %[C_e]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x0_l], %[x0_l], %[x4_l]\n\t"
      "eor %[x4_l], %[x4_l], %[x3_l]\n\t"
      "eor %[x2_l], %[x2_l], %[x1_l]\n\t"
      "movs %[tmp0], %[x0_l]\n\t"
      "bic %[tmp0], %[tmp0], %[x4_l]\n\t"
      "movs %[tmp1], %[x2_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x1_l]\n\t"
      "eor %[x0_l], %[x0_l], %[tmp1]\n\t"
      "movs %[tmp1], %[x4_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x3_l]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp1]\n\t"
      "movs %[tmp2], %[x1_l]\n\t"
      "bic %[tmp2], %[tmp2], %[x0_l]\n\t"
      "eor %[tmp2], %[x4_l], %[tmp2]\n\t"
      "movs %[tmp1], %[x3_l]\n\t"
      "bic %[tmp1], %[tmp1], %[x2_l]\n\t"
      "eor %[tmp1], %[x1_l], %[tmp1]\n\t"
      "eor %[tmp0], %[x3_l], %[tmp0]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x0_l]\n\t"
      "eor %[x0_l], %[x0_l], %[tmp2]\n\t"
      "movs %[x4_l], %[x4_h]\n\t"
      "movs %[x1_l], %[x1_h]\n\t"
      "movs %[x3_l], %[x3_h]\n\t"
      "movs %[x3_h], %[tmp0]\n\t"
      "movs %[x1_h], %[tmp1]\n\t"
      "movs %[tmp0], %[x0_h]\n\t"
      "movs %[tmp1], %[x2_h]\n\t"
      "movs %[x0_h], %[x0_l]\n\t"
      "movs %[x2_h], %[x2_l]\n\t"
      "movs %[x0_l], %[C_o]\n\t"
      "eor %[tmp1], %[tmp1], %[x0_l]\n\t"
      "eor %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[x4_l], %[x4_l], %[x3_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x1_l]\n\t"
      "movs %[x0_l], %[tmp0] \n\t"
      "bic %[x0_l], %[x0_l], %[x4_l]\n\t"
      "movs %[x2_l], %[tmp1] \n\t"
      "bic %[x2_l], %[x2_l], %[x1_l]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "movs %[x2_l], %[x4_l] \n\t"
      "bic %[x2_l], %[x2_l], %[x3_l]\n\t"
      "eor %[tmp1], %[tmp1], %[x2_l]\n\t"
      "movs %[x2_l], %[x1_l]\n\t"
      "bic %[x2_l], %[x2_l], %[tmp0]\n\t"
      "eor %[x4_l], %[x4_l], %[x2_l]\n\t"
      "movs %[x2_l], %[x3_l] \n\t"
      "bic %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[x2_l]\n\t"
      "eor %[x3_l], %[x3_l], %[x0_l]\n\t"
      "eor %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[tmp0]\n\t"
      "eor %[tmp0], %[tmp0], %[x4_l]\n\t"
      "movs %[x4_h], %[tmp1]\n\t"
      "movs %[x2_l], %[x3_h]\n\t"
      "movs %[x3_h], %[x1_l]\n\t"
      "movs %[tmp1], #17\n\t"
      "movs %[x0_l], %[tmp2]\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x0_l], %[tmp2], %[x0_l]\n\t"
      "movs %[x1_l], %[x4_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x4_l], %[x1_l]\n\t"
      "movs %[tmp1], #3\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[tmp2], %[tmp2], %[x1_l]\n\t"
      "movs %[tmp1], #4\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x4_l], %[x4_l], %[x0_l]\n\t"
      "movs %[x1_l], %[x2_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x3_l], %[x1_l]\n\t"
      "movs %[tmp1], #3\n\t"
      "movs %[x0_l], %[x3_l]\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x0_l], %[x2_l], %[x0_l]\n\t"
      "movs %[tmp1], #5\n\t"
      "ror %[x0_l], %[x0_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x2_l], %[x0_l]\n\t"
      "ror %[x1_l], %[x1_l], %[tmp1]\n\t"
      "eor %[x3_l], %[x3_l], %[x1_l]\n\t"
      "movs %[x0_l], %[x0_h]\n\t"
      "movs %[x1_l], %[x1_h]\n\t"
      "movs %[x1_h], %[x2_l]\n\t"
      "movs %[x0_h], %[tmp2]\n\t"
      "movs %[tmp2], %[x4_h]\n\t"
      "movs %[x4_h], %[x4_l]\n\t"
      "movs %[x4_l], %[x3_h]\n\t"
      "movs %[x3_h], %[x3_l]\n\t"
      "movs %[x3_l], %[x0_l]\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x3_l], %[tmp0], %[x3_l]\n\t"
      "movs %[tmp1], #4\n\t"
      "movs %[x2_l], %[tmp0]\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x0_l], %[x2_l]\n\t"
      "movs %[tmp1], #9\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x0_l], %[x0_l], %[x3_l]\n\t"
      "movs %[tmp1], #10\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[tmp0], %[tmp0], %[x2_l]\n\t"
      "movs %[tmp1], #11\n\t"
      "movs %[x2_l], %[x1_l]\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x2_l], %[x1_l], %[x2_l]\n\t"
      "movs %[x3_l], %[x4_l]\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x3_l], %[x4_l], %[x3_l]\n\t"
      "movs %[tmp1], #19\n\t"
      "ror %[x3_l], %[x3_l], %[tmp1]\n\t"
      "eor %[x1_l], %[x1_l], %[x3_l]\n\t"
      "movs %[tmp1], #20\n\t"
      "ror %[x2_l], %[x2_l], %[tmp1]\n\t"
      "eor %[x4_l], %[x4_l], %[x2_l]\n\t"
      "movs %[x2_l], %[x2_h]\n\t"
      "movs %[x3_l], %[x1_h]\n\t"
      "movs %[x1_h], %[x4_l]\n\t"
      "movs %[x2_h], %[tmp0]\n\t"
      "movs %[x4_l], #2\n\t"
      "mvn %[tmp0], %[tmp2]\n\t"
      "ror %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[tmp0], %[x2_l], %[tmp0]\n\t"
      "movs %[x4_l], #3\n\t"
      "mvn %[tmp1], %[x2_l]\n\t"
      "ror %[tmp1], %[tmp1], %[x4_l]\n\t"
      "eor %[tmp1], %[tmp2], %[tmp1]\n\t"
      "eor %[x2_l], %[x2_l], %[tmp1]\n\t"
      "movs %[x4_l], #1\n\t"
      "ror %[tmp0], %[tmp0], %[x4_l]\n\t"
      "eor %[tmp2], %[tmp2], %[tmp0]\n\t"
      "movs %[x4_l], %[x0_h]\n\t"
      "movs %[x0_h], %[x2_h]\n\t"
      "movs %[x2_h], %[tmp2]\n\t"
      :
      [x0_l] "+l"(s->w[0][0]), [x0_h] "+r"(s->w[0][1]), [x1_l] "+l"(s->w[1][0]),
      [x1_h] "+r"(s->w[1][1]), [x2_l] "+l"(s->w[2][0]), [x2_h] "+r"(s->w[2][1]),
      [x3_l] "+l"(s->w[3][0]), [x3_h] "+r"(s->w[3][1]), [x4_l] "+l"(s->w[4][0]),
      [x4_h] "+r"(s->w[4][1]), [tmp0] "=l"(tmp0), [tmp1] "=l"(tmp1),
      [tmp2] "=l"(tmp2)
      : [C_e] "ri"((uint32_t)C), [C_o] "ri"((uint32_t)(C >> 32))
      :);
  printstate(" round output", s);
}

forceinline void PROUNDS(ascon_state_t* s, int nr) {
  ROUND_LOOP(s, constants + START(nr), constants + 24);
}

#endif /* ROUND_H_ */
