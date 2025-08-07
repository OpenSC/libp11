/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
 */

#include "libp11-int.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	void *handle;
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
void *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	/* POSIX requires that the result of dlsym() is safely convertible
	 * to a function pointer, even though ISO C doesn't guarantee this. */
	union {
		CK_RV (*func)(CK_FUNCTION_LIST_PTR_PTR);
		void *data;
	} c_get_function_list;
	int rv;

	if (!mspec)
		return NULL;

	mod = OPENSSL_malloc(sizeof(sc_pkcs11_module_t));
	if (!mod)
		return NULL;
	memset(mod, 0, sizeof(sc_pkcs11_module_t));
	mod->_magic = MAGIC;

#ifdef WIN32
	mod->handle = LoadLibraryA(mspec);
#else
	mod->handle = dlopen(mspec, RTLD_LAZY | RTLD_LOCAL);
#endif

	if (!mod->handle) {
#ifndef WIN32
		pkcs11_log(NULL, LOG_ERR, "%s\n", dlerror());
#endif
		goto failed;
	}

#ifdef WIN32
	c_get_function_list.func = (CK_C_GetFunctionList)
		GetProcAddress(mod->handle, "C_GetFunctionList");
#else
	c_get_function_list.data = dlsym(mod->handle, "C_GetFunctionList");
#endif

	if (!c_get_function_list.func) {
#ifndef WIN32
		pkcs11_log(NULL, LOG_ERR, "%s\n", dlerror());
#endif
		goto failed;
	}
	rv = c_get_function_list.func(funcs);
	if (rv == CKR_OK)
		return mod;

failed:
	C_UnloadModule((void *) mod);
	return NULL;
}

/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV
C_UnloadModule(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (mod->handle) {
#ifdef WIN32
		FreeLibrary(mod->handle);
#else
		dlclose(mod->handle);
#endif
	}

	memset(mod, 0, sizeof(sc_pkcs11_module_t));
	OPENSSL_free(mod);

	return CKR_OK;
}

/* vim: set noexpandtab: */
