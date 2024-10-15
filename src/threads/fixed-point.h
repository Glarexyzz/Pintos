#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include "stdint.h"

typedef uint32_t fix_t;

#define F 16384 //1<<q, q=14

/// Representation of 1 in fixed-point.
#define FIX_1 F

/** Convert an integer to a fixed-point number.
 * @param n The integer to convert.
 */
#define INT_TO_FIX(n) ((n) * F)

/** Convert a fixed-point number to an integer, rounding towards 0.
 * @param x The fixed-point number to convert.
 */
#define FIX_TO_INT_TO_0(x) ((x) / F)

/** Convert a fixed-point number to an integer, rounding to the nearest integer.
 * @param x The fixed-point number to convert.
 */
#define FIX_TO_INT_ROUND(x) ((x) >= 0 ? \
  ((x) + F / 2) / F :                   \
  ((x) - F / 2) / F                     \
)

/** Add two fixed-point numbers.
 * @param x The first fixed-point number.
 * @param y The second fixed-point number.
 * @returns x + y, as a fixed-point number.
 */
#define FF_ADD(x, y) ((x) + (y))

/** Add a fixed-point number to an integer.
 * @param x The fixed-point number.
 * @param n The integer.
 * @returns x + n, as a fixed-point number.
 */
#define FI_ADD(x, n) ((x) + (n)*F)

/** Subtract a fixed-point number from a fixed-point number.
 * @param x The fixed-point minuend.
 * @param y The fixed-point subtrahend.
 * @returns x - y, as a fixed-point number.
 */
#define FF_SUB(x, y) ((x) - (y))

/** Subtract an integer from a fixed-point number.
 * @param x The fixed-point minuend.
 * @param n The integer subtrahend.
 * @returns x - n, as a fixed-point number.
 */
#define FI_SUB(x, n) ((x) - (n)*F)

/** Multiplies a fixed-point number by a fixed-point number.
 * @param x The multiplier.
 * @param n The multiplicand.
 * @returns x * y, as a fixed-point number.
 */
#define FF_MUL(x, y) (((int64_t) (x)) * (y) / F)

/** Multiplies a fixed-point number by an integer.
 * @param x The fixed-point number multiplier.
 * @param n The integer multiplicand.
 * @returns x * n, as a fixed-point number.
 */
#define FI_MUL(x, n) ((x) * (n))

/** Divides a fixed-point number by a fixed-point number.
 * @param x The nominator.
 * @param y The denominator.
 * @returns x / y, as a fixed-point number.
 */
#define FF_DIV(x, y) (((int64_t) (x)) * F / (y))

/** Divides a fixed-point number by an integer.
 * @param x The fixed-point number numerator.
 * @param n The integer denominator.
 * @returns x / n, as a fixed-point number.
 */
#define FI_DIV(x, n) ((x) / (n))

#endif //THREADS_FIXED_POINT_H
