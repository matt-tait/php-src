/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2015 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Zeev Suraski <zeev@zend.com>                                 |
   *         Pierre Joye <pierre@php.net>                                 |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#include "php.h"
#include <wincrypt.h>

#if _MSC_VER >= 1800	// __fastfail support added in VS2013
#	define CRYPTO_SECURITY_ERROR()	__fastfail(FAST_FAIL_CRYPTO_LIBRARY)
#else
#	define CRYPTO_SECURITY_ERROR()	abort()
#endif

PHPAPI char *php_win32_error_to_msg(DWORD error)
{
	char* buf = NULL;
	char* dupstring = NULL;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |	FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),	(LPTSTR)&buf, 0, NULL
	);

	// FormatMessage allocates a buffer on the LocalAlloc heap, but we should return a pointer to the malloc heap
	// so that callers can pass it to free.
	if (buf != NULL)
		dupstring = strdup(buf);
	if(buf != NULL)
		LocalFree(buf);

	return dupstring;
}

int php_win32_check_trailing_space(const char * path, const int path_len) {
	if (path_len < 1) {
		return 1;
	}
	if (path) {
		if (path[0] == ' ' || path[path_len - 1] == ' ') {
			return 0;
		} else {
			return 1;
		}
	} else {
		return 0;
	}
}

void CryptGenRandom64(HCRYPTPROV hCryptProv, BYTE* buf, size_t size)
{
	size_t cbRemaining = size;
	DWORD dwAmountThisLoop;
	size_t ptr = 0;

	// CryptGenRandom takes the buffer size as a DWORD, not a SIZE_T, so we may need to loop round if they are not the same (i.e. on 64-bit).
	while (ptr < size)
	{
		cbRemaining = (size - ptr);
		if (cbRemaining > MAXINT32)
			dwAmountThisLoop = MAXINT32;
		else
			dwAmountThisLoop = (DWORD)cbRemaining;

		if (!CryptGenRandom(hCryptProv, dwAmountThisLoop, &buf[ptr]))
			CRYPTO_SECURITY_ERROR();
		ptr += dwAmountThisLoop;
	}

	assert(ptr == size);
}

int php_win32_get_random_bytes(unsigned char *buf, size_t size) {

	HCRYPTPROV hCryptProv;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		CRYPTO_SECURITY_ERROR();
	}

	CryptGenRandom64(hCryptProv, buf, size);

	if (!CryptReleaseContext(hCryptProv, 0)) {
		CRYPTO_SECURITY_ERROR();
	}

	// This function always succeeds, or triggers a security abort.
	return SUCCESS;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
