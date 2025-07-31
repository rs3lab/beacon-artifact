#ifdef __cplusplus
extern "C" {
#endif
#include <linux/bpf.h>
#include <stdint.h>
int loadBTF(char *btfHolder, int btfSize);
int GenBPFProg(char *bpfProgAttr, char *bpfMapAttrs, char *bpfBtfAttt);
int CopyDone(void);
void ResetCopyDone(void);

// MAX VALUES
extern int MAXINSNSIZE;
extern int MAXFUNCINFOSIZE;
extern int MAXLINEINFOSIZE;
extern int MAXBTFSIZE;
extern int MAXMAPNUM;
extern int MAXFDARRAYSIZE;
extern int UNIONSIZE;
//
int bpfAttrSize();
int MutateBPFProg(char *insns1, char* func_info1);
unsigned long long ItmStateSize();
#ifdef __cplusplus
}
#endif
