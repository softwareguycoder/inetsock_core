// inetsock_core_symbols.h - Defines constants used throughout the library
//

#ifndef __INETSOCK_CORE_SYMBOLS_H__
#define __INETSOCK_CORE_SYMBOLS_H__

/**
 * @brief Error message that is displayed when a connect operation failed.
 */
#ifndef CONNECT_OPERATION_FAILED
#define CONNECT_OPERATION_FAILED \
	"connect: Failed to contact server on '%s' and port %d.\n"
#endif //CONNECT_OPERATION_FAILED

#ifndef CONNECTION_TERMINATED
#define CONNECTION_TERMINATED \
	"The connection with the remote host has terminated.\n"
#endif //CONNECTION_TERMINATED

#endif /* __INETSOCK_CORE_SYMBOLS_H__ */
