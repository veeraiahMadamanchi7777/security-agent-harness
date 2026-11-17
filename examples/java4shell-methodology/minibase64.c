/*
 * minibase64.c -- a DELIBERATELY BUGGY Base64 decoder, as a teaching model of
 * the CVE-2026-114938 class of bug. This is NOT the real intrinsic and NOT the
 * CVE trigger. It is a hand-written native decoder (like the JVM intrinsic)
 * containing the SAME kind of mistake: a wrong output-length calculation that
 * makes the raw pointer loop write past the end of the heap buffer.
 *
 * The point: see, concretely, how "miscount the tail -> out-of-bounds write"
 * happens in native code with no bounds checks -- the thing Java's own
 * array checks would have stopped, but the intrinsic bypasses.
 *
 * Build & run:
 *   # 1) With AddressSanitizer: the overflow is caught and located
 *   gcc -g -fsanitize=address minibase64.c -o minibase64_asan && ./minibase64_asan
 *   # 2) Without: often "works" silently -- that is the dangerous part
 *   gcc -g minibase64.c -o minibase64 && ./minibase64
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static signed char VAL(char c){
  if(c>='A'&&c<='Z')return c-'A';
  if(c>='a'&&c<='z')return c-'a'+26;
  if(c>='0'&&c<='9')return c-'0'+52;
  if(c=='+')return 62; if(c=='/')return 63; return -1;
}

/* Correct Base64 output length: 3 bytes per 4 input chars, minus padding. */
static size_t correct_out_len(const char*in,size_t n){
  size_t groups=n/4, pad=0;
  if(n>=1&&in[n-1]=='=')pad++;
  if(n>=2&&in[n-2]=='=')pad++;
  return groups*3 - pad;
}

/*
 * BUGGY decode: writes 3 output bytes for EVERY 4 input chars, including a
 * final padded group, ignoring that padding means 1 or 2 fewer output bytes.
 * So for input ending in "==" it writes 2 bytes too many -> heap overflow,
 * exactly the shape of a tail-handling miscount in a vectorized decoder.
 */
static size_t decode_buggy(const char*in,size_t n,unsigned char*out){
  size_t oi=0;
  for(size_t i=0;i+4<=n;i+=4){
    int a=VAL(in[i]),b=VAL(in[i+1]),c=VAL(in[i+2]),d=VAL(in[i+3]);
    unsigned v=((a&63)<<18)|((b&63)<<12)|((c&63)<<6)|(d&63);
    out[oi++]=(v>>16)&0xff;   /* always 3 writes, even for "XX==" */
    out[oi++]=(v>>8)&0xff;
    out[oi++]=v&0xff;
  }
  return oi;
}

int main(void){
  /* "Mw==" is valid Base64 for the single byte '3'. Correct output = 1 byte. */
  const char*attacker="Mw==";
  size_t n=strlen(attacker);
  size_t want=correct_out_len(attacker,n);       /* = 1 */

  /* A careful caller sizes the buffer to the CORRECT length. */
  unsigned char*out=malloc(want);
  printf("input=\"%s\"  correct_out_len=%zu  allocated=%zu bytes\n",attacker,want,want);

  size_t wrote=decode_buggy(attacker,n,out);     /* writes 3 -> 2 past the end */
  printf("buggy decoder wrote=%zu bytes (overflow by %zu)\n",wrote,wrote-want);

  free(out);
  return 0;
}
