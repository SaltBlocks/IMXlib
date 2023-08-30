#pragma once
#ifdef IMXLIB_EXPORTS
#include <string>
#include "ethereum.h"
#include "stark.h"
#include <curl/curl.h>
#include "nlohmann/json.hpp"
#include "constants.h"


#define IMXLIB_API __declspec(dllexport)
#else
#define IMXLIB_API __declspec(dllimport)
#endif

extern "C" struct Fee
{
	char address[43];
	double percentage;
};

extern "C" struct NFT
{
	char token_address[43];
	unsigned long long token_id;
};

#ifdef IMXLIB_EXPORTS
size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data);
std::string binToHexStr(const CryptoPP::byte* data, int len);
bool safe_copy_string(std::string result, char* output, size_t output_size);
void setupCURL(CURL* curl, std::string url, std::string method, struct curl_slist* headers, const char* data, std::string& response_string, std::string& header_string);

nlohmann::json imx_get_fee_json(Fee* fees, int fee_count);
nlohmann::json imx_get_send_nft_json(NFT* nfts, int nft_count, const char* receiver);
nlohmann::json imx_get_send_token_json(const char* token_id_str, double amount, const char* receiver);
#endif