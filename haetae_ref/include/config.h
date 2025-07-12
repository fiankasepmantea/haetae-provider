#ifndef CONFIG_H
#define CONFIG_H

#ifndef HAETAE_MODE
#define HAETAE_MODE 3 // or 2 or 5, your choice
#endif

#if HAETAE_MODE == 2
#define CRYPTO_ALGNAME "HAETAE2"
#define HAETAE_NAMESPACETOP haetae2
#define HAETAE_NAMESPACE(s) haetae2_##s
#elif HAETAE_MODE == 3
#define CRYPTO_ALGNAME "HAETAE3"
#define HAETAE_NAMESPACETOP haetae3
#define HAETAE_NAMESPACE(s) haetae3_##s
#elif HAETAE_MODE == 5
#define CRYPTO_ALGNAME "HAETAE5"
#define HAETAE_NAMESPACETOP haetae5
#define HAETAE_NAMESPACE(s) haetae5_##s
#endif

#endif