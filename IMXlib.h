#pragma once
#include <string>
#include "ethereum.h"
#include "stark.h"
#include <curl/curl.h>
#include "nlohmann/json.hpp"

#ifdef IMXLIB_EXPORTS
#define IMXLIB_API __declspec(dllexport)
#else
#define IMXLIB_API __declspec(dllimport)
#endif

extern "C" struct Fee
{
	char address[43];
	int percentage;
};

/* Calculate the signature message signed with priv_key, the result is loaded into the char buffer result. */
extern "C" IMXLIB_API char* eth_sign_message(const char* message, const char* priv_key, char* result, int resultSize);

/* Tries to cancel the order with the provided order id on IMX. */
extern "C" IMXLIB_API char* imx_cancel_order(const char* order_id_str, const char* eth_priv_str, char* result_buffer, int buffer_size);

extern "C" IMXLIB_API int imx_get_token_trade_fee(const char* token_address_str, const char* token_id, CURL * curl = NULL);

extern "C" IMXLIB_API char* imx_buy_nft(unsigned long long order_id, const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee * fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size);

extern "C" IMXLIB_API char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size);

extern "C" IMXLIB_API char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size);

extern "C" IMXLIB_API char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size);