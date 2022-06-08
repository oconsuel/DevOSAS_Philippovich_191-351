#include "Lab03Encl_t.h"

#include "sgx_trts.h"
#include <string.h>

const char table[6][41] = {
	"1BAA2126338A42868E4C0859DB78EAEA",
	"98FB6AC0E6BB4B9896BE6653D0FB68BD",
	"55AF7B6333514BFFB433898F897C38E3",
	"D485BE269E2B487681EF4121593736C1",
	"F1C41715CEA0460EA9BD7B6E93F05194"
};

void foo(char* buf, size_t len, size_t idx) {
	if (idx < 5) {
		const char* data_ptr = data_ptr = table[idx];
		memcpy(buf, data_ptr, strlen(data_ptr + 1));
	}
	else {
		memset(buf, 0, strlen(table[0]));
	}
	return;
}