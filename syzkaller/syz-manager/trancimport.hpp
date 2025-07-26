#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
int VerifyOneProg(char *progAttr, char *mapsAttr, int map_cnt, int priv, char *itm_states,
	int runtime_res, int err_lineno, char *workdir, char *dafny_veri_log, char *runtime_log, bool is_eval);
#ifdef __cplusplus
}
#endif
