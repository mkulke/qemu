#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <math.h>

static int float_equal(float a, float b, float epsilon) {
    return fabs(a - b) < epsilon;
}

int main() {
    /* Check if AVX is available via CPUID */
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1), "c"(0));

    int avx_supported = (ecx >> 28) & 1;
    int xsave_supported = (ecx >> 26) & 1;

    if (!avx_supported || !xsave_supported) {
        fprintf(stderr, "AVX or XSAVE not supported by CPU\n");
        return 1;
    }

    /* Check XCR0 (XSAVE control register) */
    uint32_t xcr0_low, xcr0_high;
    __asm__ volatile("xgetbv"
                     : "=a"(xcr0_low), "=d"(xcr0_high)
                     : "c"(0));

    if (!(xcr0_low & 4)) {
        fprintf(stderr, "AVX not enabled in XCR0\n");
        return 1;
    }

    /* Try a simple AVX operation */
    __m256 a = _mm256_set_ps(8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f);
    __m256 b = _mm256_set_ps(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f);
    __m256 c = _mm256_add_ps(a, b);

    float result[8];
    _mm256_storeu_ps(result, c);

	/* Assert correct results */
    for (int i = 0; i < 8; i++) {
		float e = 9.0f;
		int r = float_equal(result[i], e, 1e-6f);
		if (!r) {
			fprintf(stderr, "AVX test FAILED! Expected %.1f but got %.1f\n",
					e, result[i]);
			return 1;
		}
    }
    return 0;
}
