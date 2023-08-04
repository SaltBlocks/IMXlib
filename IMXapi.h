#pragma once

#ifdef IMXLIB_EXPORTS
#define IMXLIB_API __declspec(dllexport)

#include <string>
#include "ethereum.h"
#include "stark.h"
#include <curl/curl.h>
#include "nlohmann/json.hpp"
#include "constants.h"
#include "utils.h"

/* C++ implementations of IMX api functions. */
std::string imx_signable_cancel_order_details(int order_id, CURL* curl = NULL);
std::string imx_delete_order(int order_id, CryptoPP::Integer eth_address, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL);
std::string imx_signable_trade_details(unsigned long long order_id_str, const char* eth_address, nlohmann::json fee_data, CURL* curl = NULL);
std::string imx_trades(nlohmann::json signable_order, double price_limit, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL);
std::string imx_signable_order_details(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, nlohmann::json fee_data, const char* seller_address_str, CURL* curl = NULL);
std::string imx_orders(nlohmann::json signable_order, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL);
std::string imx_signable_transfer_details(nlohmann::json signable_requests, const char* sender_address_str, CURL* curl = NULL);
std::string imx_transfers(nlohmann::json signable_responses, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL);

#else
#define IMXLIB_API __declspec(dllimport)
#endif