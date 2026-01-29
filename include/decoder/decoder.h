#ifndef DECODER_H
#define DECODER_H

#include "main.h"
#include "utils/vector.h"

/**
 * prog: filters read from input
 * v:    initialized statement vector for decoded statements
 * Returns true if found any error
*/
extern bool decode_filters (fprog *prog, vector_t *v);

#endif
