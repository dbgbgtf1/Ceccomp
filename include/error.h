#define PEXIT(str, ...)                                                       \
  {                                                                           \
    printf (str, __VA_ARGS__);                                                 \
    exit (0);                                                                 \
  }
