#include <stdlib.h>
#include <linux/types.h>
#include <stdbool.h>
#include <tegra-cryptodev.h>
#include <stdio.h>

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

//#include "common.h"
//#include "tegra-crypto.h"
#include "tegra-cryptodev.h"

#define LOG printf

void tegra_crypto_op_close(void);

static int fd = -1;

int tegra_crypto_op(unsigned char *in, unsigned char *out, int len,
		    unsigned char *iv, int iv_len, int encrypt,
		    unsigned int crypto_op_mode, bool close)
{
	struct tegra_crypt_req crypt_req;
	int rc = 0;

	if (fd == -1)
		fd = open("/dev/tegra-crypto", O_RDWR);

	if (fd < 0) {
		LOG("%s: /dev/tegra-crypto open fail\n", __func__);
		return -1;
	}

	crypt_req.skip_exit = !close;
	crypt_req.op = crypto_op_mode;
	crypt_req.encrypt = encrypt;

	memset(crypt_req.key, 0, AES_KEYSIZE_128);
	crypt_req.keylen = AES_KEYSIZE_128;
	memcpy(crypt_req.iv, iv, iv_len);
	crypt_req.ivlen = iv_len;
	crypt_req.plaintext = in;
	crypt_req.plaintext_sz = len;
	crypt_req.result = out;
	crypt_req.skip_key = 0;
	crypt_req.skip_iv = 0;

	rc = ioctl(fd, TEGRA_CRYPTO_IOCTL_NEED_SSK, 1);
	if (rc < 0) {
		LOG("tegra_crypto ioctl error: TEGRA_CRYPTO_IOCTL_NEED_SSK\n");
		goto err;
	}

	rc = ioctl(fd, TEGRA_CRYPTO_IOCTL_PROCESS_REQ, &crypt_req);
	if (rc < 0) {
		LOG("tegra_crypto ioctl error: TEGRA_CRYPTO_IOCTL_PROCESS_REQ\n");
		goto err;
	}

	if (close)
		tegra_crypto_op_close();

err:
	return rc;
}

void tegra_crypto_op_close(void)
{
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
}

static void dump(const char *s, int size, int newline)
{
  for (int i = 0; i < size; i ++) {
    printf("%02x", s[i]);
    if (newline) {
      if (((i + 1) % 16) == 0) {
        printf("\n");
      }
    }
  }
}

static int to_hex(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

int main(int argc, char *argv[]) {
  unsigned char in[16] = {0};
  unsigned char out[16] = {0};
  unsigned char iv[16] = {0};
  int enc = 1;
  if (argc >= 2) {
    const char *p = argv[1];
    for (int i = 0;
      i < sizeof(in) && p[i * 2] != '\0' && p[i * 2 + 1] != '\0';
      i ++) {
      int h = to_hex(p[i * 2]) & 0xf;
      int l = to_hex(p[i * 2 + 1]) & 0xf;
      if (h < 0 || l < 0) {
        fprintf(stderr, "input is invalid\n");
        return 1;
      }
      in[i] = ((h << 4) | l);
    }
  }
  if (argc == 3) {
    const char *p = argv[2];
    if (*p == '0') {
      enc = 0;
    }
  }
  //dump(in, sizeof(in), 1);
  //dump(out, sizeof(out), 1);
  tegra_crypto_op(in, out, sizeof(in), iv, sizeof(iv), enc, TEGRA_CRYPTO_ECB, 1);
  dump(out, sizeof(out), 0);
  return EXIT_SUCCESS;
}
