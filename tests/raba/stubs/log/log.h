// Host stand-in for liblog.
#pragma once
#include <cstdio>
#define ALOGI(...) (fprintf(stderr, "I " __VA_ARGS__), fputc('\n', stderr))
#define ALOGW(...) (fprintf(stderr, "W " __VA_ARGS__), fputc('\n', stderr))
