#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
int VerifyOneProg(char *progAttr, char *mapsAttr, int map_cnt, int priv, char *itm_states,
					int runtime_res, int err_lineno, char *workdir, char *dafny_veri_log, char *runtime_log);
#ifdef __cplusplus
}
#endif
