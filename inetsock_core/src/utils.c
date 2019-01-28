///////////////////////////////////////////////////////////////////////////////
// SocketDemoUtils.c: Definitions for the functions in the SocketDemoUtils.lib
// shared library

#include <inetsock_core.h>
#include "stdafx.h"
#include "utils.h"

/**
 * \brief Checks the integer value supplied to ensure it's a valid user port
 * number and not reserved for a different service.
 * \param port Variable containing the value to be validated.
 * \returns Zero if the 'port' parameter is not in the range [1024, 49151]
 * (inclusive); nonzero otherwise.
 */
int isUserPortValid(int port)
{
    return port >= 1024 && port < 49151;
}

