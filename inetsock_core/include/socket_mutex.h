/*
 * socket_mutex.h
 *
 *  Created on: Apr 14, 2019
 *      Author: bhart
 */

#ifndef __SOCKET_MUTEX_H__
#define __SOCKET_MUTEX_H__

/**
 * @Brief Obtains a critical-section lock for socket communications if
 * CreateSocketMutex has been called.
 * @remarks For use by this library's own code only.
 */
void LockSocketMutex();

/**
 * @brief Releases the critical-section lock for socket communications.
 * @remarks Applications shuold not call this function, as it is used by
 * this library internally.
 */
void UnlockSocketMutex();

#endif /* __SOCKET_MUTEX_H__ */
