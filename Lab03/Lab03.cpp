#include <iostream>
#include <tchar.h>
#include <string.h>

#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "Lab03Encl_u.h"
#define ENCLAVE_FILE _T("Lab03Encl.signed.dll")

#define BUF_LEN 100

/* const char table[6][41] = {
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
} */

int main() {
	char buffer[BUF_LEN] = { 0 };

	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}

	while (true) {
		printf("Input index to retrieve, or -1 to exit: \t");
		int idx = -1;
		scanf_s("%d", &idx);
		if (idx < 0) {
			return 0;
		}
		foo(eid, buffer, BUF_LEN, idx);
		printf("%s\n=======================================\n\n", buffer);
	}
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}

