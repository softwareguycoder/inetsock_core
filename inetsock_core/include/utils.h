// Utils.h - File that contains prototypes for useful functions that are
// also exposed to users of this library.
//

#ifndef __UTILS_H__
#define __UTILS_H__

/**
 * \brief Checks the integer value supplied to ensure it's a valid user port
 * number and not reserved for a different service.
 * \param port Variable containing the value to be validated.
 * \returns Zero if the 'port' parameter is not in the range [1024, 49151]
 * (inclusive); nonzero otherwise.
 */
int IsUserPortValid(int port);


#endif /* __UTILS_H__ */
