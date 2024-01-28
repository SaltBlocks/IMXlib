#include "pch.h"
#include "utils.h"

bool fileExists(std::string filePath) {
    std::ifstream file(filePath);
    if (file.good()) {
        return true;
    }
    return false;
}

bool checkCurveFile(char* output, size_t output_size)
{
    using json = nlohmann::json;
    if (!fileExists("stark_curve"))
    {
        json errorRes = {
        {"code", "stark_curve_missing"},
        {"message", "Failed to locate stark_curve. This file contains the ECDSA curve parameters needed to sign transactions on IMX. Please make sure it is placed in the directory from which the program is launched."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, output, output_size);
        return false;
    }
    return true;
}

/* Used to write incoming data after a network request to a string. */
size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}

/* Converts the provided binary data to a hex string. */
std::string binToHexStr(const CryptoPP::byte* data, int len)
{
    std::stringstream ss;
    ss << std::hex << "0x";
    int i = 0;
    for (; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

/* Safely writes the result string to the output. Ensures the output will always contain a null terminated C string and no data is written past the provided output size. */
bool safe_copy_string(std::string result, char* output, size_t output_size)
{
    bool canFit = output_size >= (result.length() + 1);
    size_t toCopy = canFit ? result.length() + 1 : output_size;
    memcpy_s(output, output_size, result.c_str(), toCopy);
    if (!canFit)
    {
        output[output_size - 1] = '\0';
    }
    return canFit;
}

/* Setup the provided CURL handle for a network request to the given url with the provided data. */
void setupCURL(CURL* curl, std::string url, std::string method, struct curl_slist* headers, const char* data, std::string& response_string, std::string& header_string)
{
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (data != NULL)
    {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    }

    /* Setup base parameters for CURL */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

    /* Setup to receive return data from network request. */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
}

/* Helper functions for formatting json objects. */
nlohmann::json imx_get_fee_json(Fee* fees, int fee_count)
{
    using json = nlohmann::json;
    CryptoPP::byte market_bytes[20];
    stark::getMarketFeeAddress(market_bytes);
    json fee_data = {
            {
                { "address", binToHexStr(market_bytes, 20)}, // Marketplace fee of 1%
                { "fee_percentage", 1}
            }
    };
    for (int i = 0; i < fee_count; i++)
    {
        json user_fee = {
            { "address", fees[i].address },
            { "fee_percentage", fees[i].percentage }
        };
        fee_data.insert(fee_data.end(), user_fee);
    }
    return fee_data;
}
nlohmann::json imx_get_send_nft_json(NFT* nfts, int nft_count, const char* receiver)
{
    using json = nlohmann::json;

    json nfts_data = json::array();
    for (int i = 0; i < nft_count; i++)
    {
        json nft_data = {
            { "amount", "1" },
            { "receiver", receiver },
            { "token", {
                { "type", "ERC721"},
                { "data", {
                    { "token_address", nfts[i].token_address },
                    { "token_id", std::to_string(nfts[i].token_id) }
                    }}
                }
            }
        };
        nfts_data.insert(nfts_data.end(), nft_data);
    }
    return nfts_data;
}
nlohmann::json imx_get_send_token_json(nlohmann::json token_details, double amount, const char* receiver)
{
    using json = nlohmann::json;

    /* Gather information about the token*/
    std::string token_address_str = token_details["token_address"].get<std::string>();
    int decimals = stoi(token_details["decimals"].get<std::string>());
    int log10quantum = token_details["quantum"].get<std::string>().length() - 1;

    /* Make sure the price is within the bounds. */
    unsigned long long max_amount = ULLONG_MAX / pow(10, decimals - log10quantum);
    if (amount >= max_amount || amount <= 0)
    {
        json errorRes = {
            {"code", "invalid_data"},
            {"message", "The transfer amount was lower than 0 or exceeded the maximum that can be submitted to IMX."}
        };
        return errorRes;
    }

    /* Convert the provided amount into a string in the proper format for submitting to IMX. */
    amount *= pow(10, decimals - log10quantum);
    unsigned long long amountULL = static_cast<unsigned long long>(amount);
    std::stringstream ss;
    ss << std::dec << amountULL;
    for (int i = 0; i < log10quantum; i++)
    {
        ss << "0";
    }
    std::string amount_str = ss.str();

    /* Create the json containing the token data for the transfer. */
    json token_data;
    if (token_address_str.length() > 0)
    {
        token_data = {
            { "data", {
                { "decimals", decimals},
                { "token_address", token_address_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", decimals}}},
            { "type", token_details["symbol"].get<std::string>()}
        };
    }

    json transfer_data = { {
            { "amount", amount_str },
            { "receiver", receiver },
            { "token", token_data }
    } };
    return transfer_data;
}