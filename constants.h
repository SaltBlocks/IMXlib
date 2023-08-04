#pragma once

#ifdef IMXLIB_EXPORTS
#define IMXLIB_API __declspec(dllexport)
#else
#define IMXLIB_API __declspec(dllimport)
#endif

/* Message that once signed, is used to calculate the stark key needed to sign transactions on IMX. */
extern "C" IMXLIB_API const char imx_seed_message[73];

/* Message that once signed, is used as a key for registering an ETH address for trading on IMX. */
extern "C" IMXLIB_API const char imx_link_message[52];

/* Constant token ids used for trading specific tokens. */
extern "C" IMXLIB_API const char APE[43];
extern "C" IMXLIB_API const char CMT[43];
extern "C" IMXLIB_API const char ETH[4];
extern "C" IMXLIB_API const char GODS[43];
extern "C" IMXLIB_API const char GOG[43];
extern "C" IMXLIB_API const char IMX[43];
extern "C" IMXLIB_API const char OMI[43];
extern "C" IMXLIB_API const char USDC[43];
extern "C" IMXLIB_API const char VCO[43];
extern "C" IMXLIB_API const char VCORE[43];