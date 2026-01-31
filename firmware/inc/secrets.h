#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"

#define HSM_PIN "123456"

const static group_permission_t global_permissions[MAX_PERMS] = {
	{0x1234, true, true, true},
};

#endif  // __SECRETS_H__
