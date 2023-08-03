#include "pch.h"
#include "IMXlib.h"

// Constants
const char imx_seed_message[73] = "Only sign this request if you""\xe2\x80\x99""ve initiated an action with Immutable X.";
const char imx_link_message[52] = "Only sign this key linking request from Immutable X";
const char APE[43] = "0x4d224452801aced8b2f0aebe155379bb5d594381";
const char CMT[43] = "0xe910c2a090516fb7a7be07f96a464785f2d5dc18";
const char ETH[4] = "ETH";
const char GODS[43] = "0xccc8cb5229b0ac8069c51fd58367fd1e622afd97";
const char GOG[43] = "0x9ab7bb7fdc60f4357ecfef43986818a2a3569c62";
const char IMX[43] = "0xf57e7e7c23978c3caec3c3548e3d615c346e79ff";
const char OMI[43] = "0xed35af169af46a02ee13b9d79eb57d6d68c1749e";
const char USDC[43] = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const char VCO[43] = "0x2caa4021e580b07d92adf8a40ec53b33a215d620";
const char VCORE[43] = "0x733b5056a0697e7a4357305fe452999a0c409feb";

// utils for sending network requests.
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

// Helper functions for formatting json objects.
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
nlohmann::json imx_get_send_token_json(const char* token_id_str, double amount, const char* receiver)
{
    using json = nlohmann::json;
    /* Make sure the price is within the bounds. */
    int decimals = !std::strcmp(token_id_str, USDC) ? 6 : 18;
    int log10quantum = !std::strcmp(token_id_str, USDC) ? 0 : 8;
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
    if (!strncmp(token_id_str, "0x", 2))
    {
        token_data = {
            { "data", {
                { "decimals", decimals},
                { "token_address", token_id_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", decimals}}},
            { "type", token_id_str}
        };
    }

    json transfer_data = { {
            { "amount", amount_str },
            { "receiver", receiver },
            { "token", token_data }
    } };
    return transfer_data;
}

// IMX api functions
std::string imx_signable_cancel_order_details(int order_id, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    bool create_curl = curl == NULL;
    /* Create json string for requesting order deletion details. */
    json details = { { "order_id", order_id } };
    std::string details_str = details.dump();

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    if (create_curl)
        curl = curl_easy_init();
    std::string response_string;
    std::string header_string;
    setupCURL(curl, "https://api.x.immutable.com/v3/signable-cancel-order-details", "POST", headers, details_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_reach_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        std::string errorStr = errorRes.dump();
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorStr;
    }

    /* The request succeeded, return the data from the server. */
    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.
    return response_string;
}
std::string imx_delete_order(int order_id, CryptoPP::Integer eth_address, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    bool create_curl = curl == NULL;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    if (create_curl)
        curl = curl_easy_init();
    std::string response_string;
    std::string header_string;

    /* Calculate signatures for cancelling the order. */
    byte b_eth_address[20];
    eth_address.Encode(b_eth_address, 20);
    byte eth_sign[65];
    Integer(imx_signature).Encode(eth_sign, 65);
    eth_sign[64] %= 27;
    byte cancel_sign[64];
    stark::signHash(stark::getCancelHash(order_id), stark_key).Encode(cancel_sign, 64);

    /* Transform the signatures to strings we can pass to IMX. */
    
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += binToHexStr(b_eth_address, 20);
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);
    json cancelData = {
        {"stark_signature", binToHexStr(cancel_sign, 64)}
    };
    std::string cancelStr = cancelData.dump();

    /* Create the URL that we can contact to execute the order deletion request. */
    std::string cancel_url = "https://api.x.immutable.com/v3/orders/";
    cancel_url += std::to_string(order_id);

    /* Update the headers to include the message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Setup the details for the deletion request. */
    response_string.clear();
    header_string.clear();
    setupCURL(curl, cancel_url.c_str(), "DELETE", headers, cancelStr.c_str(), response_string, header_string);

    /* Execute the request and cleanup CURL. */
    int con = curl_easy_perform(curl);
    if (create_curl)
        curl_easy_cleanup(curl);

    /* Return the result */
    return response_string;
}
std::string imx_signable_trade_details(unsigned long long order_id_str, const char* eth_address, nlohmann::json fee_data, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    bool create_curl = curl == NULL;

    /* Create CURL instance. */
    if (create_curl)
        curl = curl_easy_init();

    json request_data = {
        { "user", eth_address },
        { "order_id", order_id_str },
        { "fees", fee_data }
    };
    std::string request_str = request_data.dump();

    /* URL for requesting the signable order. */
    std::string request_url = "https://api.x.immutable.com/v3/signable-trade-details";

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    std::string response_string;
    std::string header_string;
    setupCURL(curl, request_url, "POST", headers, request_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);
    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        std::string errorStr = errorRes.dump();
        return errorStr;
    }

    return response_string;
}
std::string imx_trades(nlohmann::json signable_order, double price_limit, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Format the Recovery ID of the eth signature. */
    byte eth_sign[65];
    imx_signature.Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Collect all data needed to sign the transaction. */
#pragma warning( push )
#pragma warning( disable : 4244)
    Integer eth_address(signable_order["eth_address"].get<std::string>().c_str());
    Integer vault_sell = signable_order["vault_id_sell"].get<__int64>();
    Integer vault_buy = signable_order["vault_id_buy"].get<__int64>();
    Integer vault_fee = signable_order["fee_info"]["source_vault_id"].get<__int64>();
    Integer amount_sell(signable_order["amount_sell"].get<std::string>().c_str());
    Integer amount_buy(signable_order["amount_buy"].get<std::string>().c_str());
    Integer amount_fee(signable_order["fee_info"]["fee_limit"].get<std::string>().c_str());
    Integer token_sell(signable_order["asset_id_sell"].get<std::string>().c_str());
    Integer token_buy(signable_order["asset_id_buy"].get<std::string>().c_str());
    Integer token_fee(signable_order["fee_info"]["asset_id"].get<std::string>().c_str());
    Integer nonce = signable_order["nonce"].get<__int64>();
    Integer expiration_timestamp = signable_order["expiration_timestamp"].get<__int64>();
#pragma warning( pop )

    /* Make sure the price is lower than the maximum provided by the user. */
    int decimals = !std::strcmp(signable_order["asset_id_sell"].get<std::string>().c_str(), USDC) ? 6 : 10;
    Integer price_total = amount_sell + amount_fee;
    
    std::stringstream ss;
    ss << std::dec << std::fixed << std::setprecision(0) << price_limit * pow(10, decimals);
    Integer max_val(ss.str().c_str());

    if (price_total > max_val)
    {
        json errorRes = {
            {"code", "price_limit_exceeded"},
            {"message", "Buying this order would cost more than the provided price limit."}
        };
        return errorRes.dump();
    }

    /* Create the order hash and sign it. */
    Integer order_hash = stark::getOrderHash(vault_sell, vault_buy, amount_sell, amount_buy, token_sell, token_buy, nonce, expiration_timestamp, token_fee, vault_fee, amount_fee);
    Integer stark_sign = stark::signHash(order_hash, stark_key);

    /* Encode the signature into a string. */
    byte stark_sign_bytes[64];
    stark_sign.Encode(stark_sign_bytes, 64);
    std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

    /* Properly format the signed order. */
    json order_data = {
        { "stark_key", signable_order["stark_key"] },
        { "amount_sell", signable_order["amount_sell"] },
        { "asset_id_sell", signable_order["asset_id_sell"] },
        { "vault_id_sell", signable_order["vault_id_sell"] },
        { "amount_buy", signable_order["amount_buy"] },
        { "asset_id_buy", signable_order["asset_id_buy"] },
        { "vault_id_buy", signable_order["vault_id_buy"] },
        { "expiration_timestamp", signable_order["expiration_timestamp"] },
        { "nonce", signable_order["nonce"] },
        { "stark_signature", stark_signature },
        { "order_id", signable_order["order_id"] },
        { "fee_info", signable_order["fee_info"] },
        { "fees", signable_order["fee_json"] }
    };

    std::string order_str = order_data.dump();

    /* Determine if a new CURL instance should be created. */
    bool create_curl = curl == NULL;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    if (create_curl)
        curl = curl_easy_init();
    std::string response_string;
    std::string header_string;

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    byte b_eth_address[20];
    eth_address.Encode(b_eth_address, 20);
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += binToHexStr(b_eth_address, 20);
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);

    /* Update the headers to include the address and message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Prepare to submit the signed order. */
    std::string submit_url = "https://api.x.immutable.com/v3/trades";
    setupCURL(curl, submit_url, "POST", headers, order_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorRes.dump();
    }

    /* Cleanup curl*/
    if (create_curl)
        curl_easy_cleanup(curl);

    /* Copy and return the result */
    return response_string;

    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.
    return order_str;
}
std::string imx_signable_order_details(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, nlohmann::json fee_data, const char* seller_address_str, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;
    
    /* Create CURL instance. */
    bool create_curl = curl == NULL;
    if (create_curl)
        curl = curl_easy_init();

    /* Make sure the price is within the bounds. */
    unsigned long long max_price = ULLONG_MAX / 10000000000;

    if (price >= max_price || price <= 0)
    {
        json errorRes = {
            {"code", "invalid_data"},
            {"message", "The offer price was lower than 0 or exceeded the maximum offer price that can be submitted to IMX."}
        };
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorRes.dump();
    }

    /* Convert the provided price into a string in the proper format for submitting to IMX. */
    int decimals = !std::strcmp(token_id_str, USDC) ? 6 : 18;
    int log10quantum = !std::strcmp(token_id_str, USDC) ? 0 : 8;
    price *= pow(10, decimals - log10quantum);
    unsigned long long priceULL = static_cast<unsigned long long>(price);
    std::stringstream ss;
    ss << std::dec << priceULL;
    for (int i = 0; i < log10quantum; i++)
    {
        ss << "0";
    }
    std::string price_str = ss.str();

    /* Format the json for the token we are looking to receive, if this starts with 0x we'll assume it is an ERC20 token and the token address was provided. */
    json token_data;
    if (!strncmp(token_id_str, "0x", 2))
    {
        token_data = {
            { "data", {
                { "decimals", decimals},
                { "token_address", token_id_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", decimals}}},
            { "type", token_id_str}
        };
    }

    /* Create the json string for requesting the order we can sign. */
    json request_data = {
        { "token_buy", token_data},
        { "token_sell", {
            { "data", {
                { "token_address", nft_address_str },
                { "token_id", nft_id_str }
                }
            },
            { "type", "ERC721" }
            }
        },
        { "fees", fee_data },
        { "amount_buy", price_str },
        { "amount_sell", "1"},
        { "expiration_timestamp", 1721854840},
        { "split_fees", true },
        { "user", seller_address_str}
    };
    std::string req = request_data.dump();

    /* URL for requesting the signable order. */
    std::string request_url = "https://api.x.immutable.com/v3/signable-order-details";

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    std::string response_string;
    std::string header_string;
    setupCURL(curl, request_url, "POST", headers, req.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorRes.dump();
    }
    
    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.
    return response_string;
}
std::string imx_orders(nlohmann::json signable_order, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    bool create_curl = curl == NULL;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    if (create_curl)
        curl = curl_easy_init();
    std::string response_string;
    std::string header_string;

    /* Sign the message. */
    byte eth_sign[65];
    imx_signature.Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Collect all data needed to sign the transaction. */
#pragma warning( push )
#pragma warning( disable : 4244)
    Integer eth_address(signable_order["eth_address"].get<std::string>().c_str());
    Integer vault_sell = signable_order["vault_id_sell"].get<__int64>();
    Integer vault_buy = signable_order["vault_id_buy"].get<__int64>();
    Integer vault_fee = signable_order["fee_info"]["source_vault_id"].get<__int64>();
    Integer amount_sell(signable_order["amount_sell"].get<std::string>().c_str());
    Integer amount_buy(signable_order["amount_buy"].get<std::string>().c_str());
    Integer amount_fee(signable_order["fee_info"]["fee_limit"].get<std::string>().c_str());
    Integer token_sell(signable_order["asset_id_sell"].get<std::string>().c_str());
    Integer token_buy(signable_order["asset_id_buy"].get<std::string>().c_str());
    Integer token_fee(signable_order["fee_info"]["asset_id"].get<std::string>().c_str());
    Integer nonce = signable_order["nonce"].get<__int64>();
    Integer expiration_timestamp = signable_order["expiration_timestamp"].get<__int64>();
#pragma warning( pop )

    /* Create the order hash and sign it. */
    Integer order_hash = stark::getOrderHash(vault_sell, vault_buy, amount_sell, amount_buy, token_sell, token_buy, nonce, expiration_timestamp, token_fee, vault_fee, amount_fee);
    Integer stark_sign = stark::signHash(order_hash, stark_key);

    /* Encode the signature into a string. */
    byte stark_sign_bytes[64];
    stark_sign.Encode(stark_sign_bytes, 64);
    std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

    byte b_eth_address[20];
    eth_address.Encode(b_eth_address, 20);

    /* Properly format the signed order. */
    json order_data = {
        { "stark_key", signable_order["stark_key"] },
        { "amount_sell", signable_order["amount_sell"] },
        { "asset_id_sell", signable_order["asset_id_sell"] },
        { "vault_id_sell", signable_order["vault_id_sell"] },
        { "amount_buy", signable_order["amount_buy"] },
        { "asset_id_buy", signable_order["asset_id_buy"] },
        { "vault_id_buy", signable_order["vault_id_buy"] },
        { "expiration_timestamp", signable_order["expiration_timestamp"] },
        { "nonce", signable_order["nonce"] },
        { "stark_signature", stark_signature },
        { "fees", signable_order["fee_json"] }
    };

    std::string order_str = order_data.dump();

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += binToHexStr(b_eth_address, 20);
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);

    /* Update the headers to include the address and message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Prepare to submit the signed order. */
    std::string submit_url = "https://api.x.immutable.com/v3/orders";
    setupCURL(curl, submit_url, "POST", headers, order_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorRes.dump();
    }

    /* Cleanup curl*/
    if (create_curl)
        curl_easy_cleanup(curl);

    /* Copy and return the result */
    return response_string;
}
std::string imx_signable_transfer_details(nlohmann::json signable_requests, const char* sender_address_str, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    bool create_curl = curl == NULL;
    if (create_curl)
        curl = curl_easy_init();

    /* Create the json string for requesting the order we can sign. */
    json request_data = {
        { "sender_ether_key", sender_address_str },
        { "signable_requests", signable_requests }
    };
    std::string req = request_data.dump();

    /* URL for requesting the signable transfer. */
    std::string request_url = "https://api.x.immutable.com/v2/signable-transfer-details";

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    std::string response_string;
    std::string header_string;
    setupCURL(curl, request_url, "POST", headers, req.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        if (create_curl)
            curl_easy_cleanup(curl); // Cleanup CURL.
        return errorRes.dump();
    }

    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.

    return response_string;
}
std::string imx_transfers(nlohmann::json signable_responses, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl = NULL)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Loop through every transfer and sign each individually. Signed transfers are stored in requests_json */
    json requests_json = json::array();
    for (json signable : signable_responses["signable_responses"])
    {
        /* Collect all data needed to sign the transfer. */
#pragma warning( push )
#pragma warning( disable : 4244)
        std::string token_id_str = signable["asset_id"].get<std::string>();
        Integer amount(signable["amount"].get<std::string>().c_str());
        if (amount != 1)
        {
            /*
                The amount used to generate the signature hash when transfering a token (ETH/ERC20) needs to be divided by 10 ^ log10quantum.
                For all currencies except USDC this is 10^8.
            */
            int log10quantum = !std::strcmp(token_id_str.c_str(), USDC) ? 0 : 8;
            amount /= pow(10, log10quantum);
        }
        Integer nonce = signable["nonce"].get<__int64>();
        Integer sender_vault_id = signable["sender_vault_id"].get<__int64>();
        Integer token(token_id_str.c_str());
        Integer receiver_vault_id = signable["receiver_vault_id"].get<__int64>();
        Integer receiver_public_key(signable["receiver_stark_key"].get<std::string>().c_str());
        Integer expiration_timestamp = signable["expiration_timestamp"].get<__int64>();
#pragma warning( pop )

        /* Create the transfer hash and sign it. */
        Integer transfer_hash = stark::getTransferHash(amount, nonce, sender_vault_id, token, receiver_vault_id, receiver_public_key, expiration_timestamp);
        Integer stark_sign = stark::signHash(transfer_hash, stark_key);

        /* Encode the signature into a string. */
        byte stark_sign_bytes[64];
        stark_sign.Encode(stark_sign_bytes, 64);
        std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

        /* Create the signed json that can be submitted to the server and add it to requests_json. */
        json json_transfer = {
            { "receiver_stark_key", signable["receiver_stark_key"] },
            { "receiver_vault_id", signable["receiver_vault_id"] },
            { "amount", signable["amount"] },
            { "asset_id", signable["asset_id"] },
            { "expiration_timestamp", signable["expiration_timestamp"] },
            { "nonce", signable["nonce"] },
            { "sender_vault_id", signable["sender_vault_id"] },
            { "stark_signature", stark_signature }
        };
        requests_json.insert(requests_json.end(), json_transfer);
    }

    /* Properly format the message encompassing all transfers. */
    json transfer_data = {
        { "sender_stark_key", signable_responses["sender_stark_key"] },
        { "requests", requests_json }
    };
    std::string transfer_str = transfer_data.dump();

    /* Determine if a new CURL instance should be created. */
    bool create_curl = curl == NULL;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup CURL and objects to receive data. */
    if (create_curl)
        curl = curl_easy_init();
    std::string response_string;
    std::string header_string;

    /* Format the Recovery ID of the eth signature. */
    byte eth_sign[65];
    imx_signature.Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += signable_responses["eth_address"].get<std::string>();
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);

    /* Update the headers to include the address and message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Prepare to submit the signed transfer. */
    std::string submit_url = "https://api.x.immutable.com/v2/transfers";
    response_string.clear();
    header_string.clear();
    setupCURL(curl, submit_url, "POST", headers, transfer_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Cleanup curl*/
    if (create_curl)
        curl_easy_cleanup(curl);

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        return errorRes.dump();
    }

    return response_string;
}

// Storage for requested orders.
std::unordered_map<std::string, nlohmann::json> requested_buys;
std::unordered_map<std::string, nlohmann::json> requested_sales;
std::unordered_map<std::string, nlohmann::json> requested_transfers;

/* Randomly generates a new ethereum private key. */
char* eth_generate_key(char* result_buffer, int buffer_size)
{
    using CryptoPP::Integer;
    using CryptoPP::byte;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());
    Integer x = privateKey.GetPrivateExponent();
    byte key_bytes[32];
    x.Encode(key_bytes, 32);
    safe_copy_string(binToHexStr(key_bytes, 32), result_buffer, buffer_size);
    return result_buffer;
}

char* eth_get_address(const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using CryptoPP::Integer;
    using CryptoPP::byte;

    byte address[20];
    ethereum::getAddress(CryptoPP::Integer(eth_priv_str)).Encode(address, 20);
    safe_copy_string(binToHexStr(address, 20), result_buffer, buffer_size);
    return result_buffer;
}

char* eth_sign_message(const char* message_str, const char* priv_key, char* result_buffer, int buffer_size)
{
	/* Define components of CryptoPP we're using for ease of use. */
	using CryptoPP::Integer;
	using CryptoPP::byte;
	using namespace std;

	/* Convert the private key string to an integer. */
	Integer priv(priv_key);

	/* Calculate the signature and store in a string. */
	Integer sig = ethereum::signMessage(message_str, priv);
	byte sigBytes[65];
	sig.Encode(sigBytes, 65);
	string sig_str = binToHexStr(sigBytes, 65);

	/* Copy the signature into the provided output. */
	safe_copy_string(sig_str, result_buffer, buffer_size);

	/* Return the output. */
	return result_buffer;
}

char* imx_register_address_presigned(const char* eth_address_str, const char* link_sig_str, const char* seed_sig_str, char* result_buffer, int buffer_size)
{
    /* Define components of CryptoPP we're using for ease of use. */
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Declare byte arrays for the data we will send to IMX.*/
    byte eth_address_bytes[20];
    byte stark_address_bytes[32];
    byte eth_sig_bytes[65];
    byte stark_sig_bytes[64];

    /* Calculate the stark private key and stark address that corresponds to the provided eth key. */
    Integer eth_address(eth_address_str);
    Integer stark_priv = stark::getStarkPriv(eth_address, Integer(seed_sig_str));
    Integer stark_address = stark::getAddress(stark_priv);
    Integer eth_sig(link_sig_str);

    /* Calculate the signatures needed to link the L1 and L2 wallets. */
    eth_address.Encode(eth_address_bytes, 20);
    stark_address.Encode(stark_address_bytes, 32);
    eth_sig.Encode(eth_sig_bytes, 65);
    eth_sig_bytes[64] %= 27;
    stark::signHash(stark::getRegisterHash(eth_address, stark_address), stark_priv).Encode(stark_sig_bytes, 64);

    /* Create json string containing the data for linking the ethereum and stark wallets. */
    json details = { 
        { "ether_key",  eth_address_str },
        { "stark_key", binToHexStr(stark_address_bytes, 32) },
        { "stark_signature", binToHexStr(stark_sig_bytes, 64) },
        { "eth_signature", binToHexStr(eth_sig_bytes, 65) }
    };
    std::string linking_str = details.dump();

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    CURL* curl;
    curl = curl_easy_init();
    std::string response_string;
    std::string header_string;
    setupCURL(curl, "https://api.x.immutable.com/v1/users", "POST", headers, linking_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Cleanup CURL. */
    curl_easy_cleanup(curl);

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_reach_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        return result_buffer;
    }

    /* Return the message returned by IMX. */
    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_register_address(const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    /* Define components of CryptoPP we're using for ease of use. */
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Declare byte arrays for the data we will send to IMX.*/
    byte eth_address_bytes[20];
    byte stark_address_bytes[32];
    byte eth_sig_bytes[65];
    byte stark_sig_bytes[64];

    /* Calculate the stark private key and stark address that corresponds to the provided eth key. */
    Integer eth_priv = Integer(eth_priv_str);
    Integer stark_priv = stark::getStarkPriv(eth_priv);
    Integer eth_address = ethereum::getAddress(eth_priv);
    Integer stark_address = stark::getAddress(stark_priv);
    Integer eth_sig = ethereum::signMessage(imx_link_message, eth_priv);

    /* Calculate the signatures needed to link the L1 and L2 wallets. */
    eth_address.Encode(eth_address_bytes, 20);
    stark_address.Encode(stark_address_bytes, 32);
    eth_sig.Encode(eth_sig_bytes, 65);
    eth_sig_bytes[64] %= 27;
    stark::signHash(stark::getRegisterHash(eth_address, stark_address), stark_priv).Encode(stark_sig_bytes, 64);

    /* Create json string containing the data for linking the ethereum and stark wallets. */
    json details = { 
        { "ether_key",  binToHexStr(eth_address_bytes, 20) },
        { "stark_key", binToHexStr(stark_address_bytes, 32) },
        { "stark_signature", binToHexStr(stark_sig_bytes, 64) },
        { "eth_signature", binToHexStr(eth_sig_bytes, 65) }
    };
    std::string linking_str = details.dump();

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    CURL* curl;
    curl = curl_easy_init();
    std::string response_string;
    std::string header_string;
    setupCURL(curl, "https://api.x.immutable.com/v1/users", "POST", headers, linking_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Cleanup CURL. */
    curl_easy_cleanup(curl);

    /* Check if the request was successful, if it wasn't, return a json string with an error message. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_reach_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        return result_buffer;
    }

    /* Return the message returned by IMX. */
    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_request_cancel_order(const char* order_id_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    std::string response_string = imx_signable_cancel_order_details(std::stoi(order_id_str));

    /* The request succeeded, check if it contained the requested data, otherwise return this data as error. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the deletion request and return this. */
    std::string sign_str = response_data["signable_message"].get<std::string>();
    safe_copy_string(sign_str, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_finish_cancel_order(const char* order_id_str, const char * eth_address_str, const char * imx_seed_sig_str, const char * imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    Integer address(eth_address_str);
    std::string result = imx_delete_order(std::stoi(order_id_str), address, stark::getStarkPriv(address, Integer(imx_seed_sig_str)), Integer(imx_transaction_sig_str));

    /* Copy and return the result */
    safe_copy_string(result, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_cancel_order(const char* order_id_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Setup CURL. */
    CURL* curl;
    curl = curl_easy_init();

    /* Fetch the signature that needs to be signed to cancel the order. */
    std::string details_string = imx_signable_cancel_order_details(std::stoi(order_id_str), curl);

    /* The request succeeded, check if it contained the requested data, otherwise return this data as error. */
    json response_data = json::parse(details_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(details_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the deletion request. */
    std::string sign_str = response_data["signable_message"].get<std::string>();

    /* Sign the transaction with the user's STARK private key and the submit message using the ethereum private key. */
    Integer eth_priv = Integer(eth_priv_str);
    Integer stark_key = stark::getStarkPriv(eth_priv);
    std::string result = imx_delete_order(std::stoi(order_id_str), ethereum::getAddress(eth_priv), stark_key, ethereum::signMessage(sign_str, eth_priv), curl);

    /* Cleanup CURL */
    curl_easy_cleanup(curl);

    /* Copy and return the result */
    safe_copy_string(result, result_buffer, buffer_size);
    return result_buffer;
}

int imx_get_token_trade_fee(const char* token_address_str, const char* token_id_str)
{
    using json = nlohmann::json;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Create the URL for getting the fee amounts. */
    std::stringstream ss;
    ss << "https://api.x.immutable.com/v1/assets/" << token_address_str << "/" << token_id_str << "?include_fees=true";
    std::string fee_url = ss.str();
    
    /* Setup url and data to send. */
    CURL* curl = curl_easy_init();

    std::string response_string;
    std::string header_string;
    setupCURL(curl, fee_url, "GET", headers, NULL, response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Cleanup curl*/
    curl_easy_cleanup(curl);

    /* Check if the request was successful, if it wasn't, return -1 to indicate an error. */
    json data = json::parse(response_string);
    if (con != 0 || !data.contains("fees"))
    {
        return -1; // return error
    }

    /* Calcualte the base fee percentage. */
    json fee_data = data["fees"];
    int fee_percentage = 0;
    for (int i = 0; i < fee_data.size(); i++)
    {
        fee_percentage += fee_data[i]["percentage"].get<int>();
    }
    return fee_percentage; // Most marketplaces will add a 1% taker fee to this percentage, this also excludes the maker marketplace fee.
}

char* imx_request_buy_nft(const char* order_id_str, const char* eth_address_str, Fee* fees, int fee_count, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;
    
    json fee_json = imx_get_fee_json(fees, fee_count);
    std::string response_string = imx_signable_trade_details(std::stoull(order_id_str), eth_address_str, fee_json);
    
    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message") || !response_data.contains("nonce"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    response_data["eth_address"] = eth_address_str;
    response_data["order_id"] = std::stoull(order_id_str);
    response_data["fee_json"] = fee_json;
    requested_buys.insert(std::pair<std::string, json>(std::to_string(response_data["nonce"].get<__int64>()), response_data));
    json result = {
            {"nonce", response_data["nonce"].get<__int64>()},
            {"signable_message", response_data["signable_message"].get<std::string>()}
    };
    safe_copy_string(result.dump(), result_buffer, buffer_size);
    return result_buffer;
}

char* imx_finish_buy_nft(const char* nonce_str, double price_limit, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Look for a requested order with the provided nonce. */
    if (requested_buys.find(nonce_str) == requested_buys.end())
    {
        json errorRes = {
            {"code", "request_not_found"},
            {"message", "Could not find a request for the provided nonce."}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        return result_buffer;
    }
    json signable_order = requested_buys[nonce_str];
    requested_buys.erase(nonce_str); // Erase the order from the requested orders list if it was found.
    Integer stark_key = stark::getStarkPriv(Integer(signable_order["eth_address"].get<std::string>().c_str()), Integer(imx_seed_sig_str)); // Calculate the users stark key.
    std::string result = imx_trades(signable_order, price_limit, stark_key, Integer(imx_transaction_sig_str)); // Send the order to IMX.

    /* Return the result. */
    safe_copy_string(result, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_buy_nft(const char* order_id_str, double price_limit, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    json fee_json = imx_get_fee_json(fees, fee_count);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(imx_signable_trade_details(std::stoull(order_id_str), address_str.c_str(), fee_json, curl));
    if (!response_data.contains("signable_message") || !response_data.contains("nonce"))
    {
        safe_copy_string(response_data.dump(), result_buffer, buffer_size);
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    response_data["eth_address"] = address_str;
    response_data["order_id"] = std::stoull(order_id_str);
    response_data["fee_json"] = fee_json;

    std::string message = response_data["signable_message"].get<std::string>();
    Integer stark_key = stark::getStarkPriv(eth_priv);
    Integer imx_signature = ethereum::signMessage(message, eth_priv);

    std::string result = imx_trades(response_data, price_limit, stark_key, imx_signature, curl);

    safe_copy_string(result, result_buffer, buffer_size);
    curl_easy_cleanup(curl); // Cleanup CURL.
    return result_buffer;
}

char* imx_request_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* seller_address_str, char* result_buffer, int buffer_size, CURL* curl)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    bool create_curl = curl == NULL;
    if (create_curl)
        curl = curl_easy_init();

    json fee_json = imx_get_fee_json(fees, fee_count);
    std::string response_string = imx_signable_order_details(nft_address_str, nft_id_str, token_id_str, price, fee_json, seller_address_str);

    
    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message") || !response_data.contains("nonce"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }
    
    /* Extract the message that we need to sign to submit the order. */
    response_data["eth_address"] = seller_address_str;
    response_data["fee_json"] = fee_json;
    requested_sales.insert(std::pair<std::string, json>(std::to_string(response_data["nonce"].get<__int64>()), response_data));
    json result = {
            {"nonce", response_data["nonce"].get<__int64>()},
            {"signable_message", response_data["signable_message"].get<std::string>()}
    };
    
    safe_copy_string(result.dump(), result_buffer, buffer_size);
    if (create_curl)
        curl_easy_cleanup(curl); // Cleanup CURL.
    return result_buffer;
}

char* imx_finish_sell_nft(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    if (requested_sales.find(nonce_str) == requested_sales.end())
    {
        json errorRes = {
            {"code", "request_not_found"},
            {"message", "Could not find a request for the provided nonce."}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        return result_buffer;
    }
    json signable_order = requested_sales[nonce_str];
    requested_sales.erase(nonce_str);
    Integer stark_key = stark::getStarkPriv(Integer(signable_order["eth_address"].get<std::string>().c_str()), Integer(imx_seed_sig_str));
    std::string result = imx_orders(signable_order, stark_key, Integer(imx_transaction_sig_str));

    safe_copy_string(result, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    json fee_json = imx_get_fee_json(fees, fee_count);
    json response_data = json::parse(imx_signable_order_details(nft_address_str, nft_id_str, token_id_str, price, fee_json, address_str.c_str(), curl));

    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_data.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    response_data["eth_address"] = address_str;
    response_data["fee_json"] = fee_json;

    std::string message = response_data["signable_message"].get<std::string>();
    Integer stark_key = stark::getStarkPriv(eth_priv);
    Integer imx_signature = ethereum::signMessage(message, eth_priv);
    
    std::string result = imx_orders(response_data, stark_key, imx_signature, curl);

    safe_copy_string(result, result_buffer, buffer_size);
    curl_easy_cleanup(curl); // Cleanup CURL.
    return result_buffer;
}

char* imx_request_transfer_nfts(NFT* nfts, int nft_count, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    if (nft_count <= 0)
    {
        json errorRes = {
            {"code", "No NFT's selected."},
            {"message", "Select at least one NFT to transfer."}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        return result_buffer;
    }

    std::string response_string = imx_signable_transfer_details(imx_get_send_nft_json(nfts, nft_count, receiver_address_str), sender_address_str);
    
    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }

    response_data["eth_address"] = sender_address_str;
    requested_transfers.insert(std::pair<std::string, json>(std::to_string(response_data["signable_responses"][0]["nonce"].get<__int64>()), response_data));
    json result = {
            {"nonce", response_data["signable_responses"][0]["nonce"].get<__int64>() },
            {"signable_message", response_data["signable_message"].get<std::string>()}
    };
    safe_copy_string(result.dump(), result_buffer, buffer_size);
    return result_buffer;
}

char* imx_request_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size)
{
    NFT nft;
    strncpy_s(nft.token_address, nft_address_str, 42);
    nft.token_address[42] = '\0'; // Ensure null termination
    nft.token_id = std::stoull(nft_id_str);
    return imx_request_transfer_nfts(&nft, 1, receiver_address_str, sender_address_str, result_buffer, buffer_size);
}

char* imx_transfer_nfts(NFT* nfts, int nft_count, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    if (nft_count <= 0)
    {
        json errorRes = {
            {"code", "No NFT's selected."},
            {"message", "Select at least one NFT to transfer."}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        return result_buffer;
    }

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    std::string response_string = imx_signable_transfer_details(imx_get_send_nft_json(nfts, nft_count, receiver_address_str), address_str.c_str(), curl);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    response_data["eth_address"] = address_str;

    /* Calculate signatures needed to complete the transfer. */
    std::string message = response_data["signable_message"].get<std::string>();
    Integer stark_key = stark::getStarkPriv(eth_priv);
    Integer imx_signature = ethereum::signMessage(message, eth_priv);
    std::string result = imx_transfers(response_data, stark_key, imx_signature, curl);

    safe_copy_string(result, result_buffer, buffer_size);
    curl_easy_cleanup(curl); // Cleanup CURL.
    return result_buffer;
}

char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    NFT nft;
    strncpy_s(nft.token_address, nft_address_str, 42);
    nft.token_address[42] = '\0'; // Ensure null termination
    nft.token_id = std::stoull(nft_id_str);
    return imx_transfer_nfts(&nft, 1, receiver_address_str, eth_priv_str, result_buffer, buffer_size);
}

char* imx_request_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    json transfer_data = imx_get_send_token_json(token_id_str, amount, receiver_address_str);
    if (transfer_data.contains("code"))
    {
        safe_copy_string(transfer_data.dump(), result_buffer, buffer_size);
        return result_buffer;
    }

    std::string response_string = imx_signable_transfer_details(transfer_data, sender_address_str);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }

    response_data["eth_address"] = sender_address_str;
    requested_transfers.insert(std::pair<std::string, json>(std::to_string(response_data["signable_responses"][0]["nonce"].get<__int64>()), response_data));
    json result = {
            {"nonce", response_data["signable_responses"][0]["nonce"].get<__int64>() },
            {"signable_message", response_data["signable_message"].get<std::string>()}
    };
    safe_copy_string(result.dump(), result_buffer, buffer_size);
    return result_buffer;
}

char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    json transfer_data = imx_get_send_token_json(token_id_str, amount, receiver_address_str);
    if (transfer_data.contains("code"))
    {
        safe_copy_string(transfer_data.dump(), result_buffer, buffer_size);
        return result_buffer;
    }

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    std::string response_string = imx_signable_transfer_details(transfer_data, address_str.c_str(), curl);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    response_data["eth_address"] = address_str;

    /* Calculate signatures needed to complete the transfer. */
    std::string message = response_data["signable_message"].get<std::string>();
    Integer stark_key = stark::getStarkPriv(eth_priv);
    Integer imx_signature = ethereum::signMessage(message, eth_priv);
    std::string result = imx_transfers(response_data, stark_key, imx_signature, curl);

    safe_copy_string(result, result_buffer, buffer_size);
    curl_easy_cleanup(curl); // Cleanup CURL.
    return result_buffer;
}

char* imx_finish_transfer(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    if (requested_transfers.find(nonce_str) == requested_transfers.end())
    {
        json errorRes = {
            {"code", "request_not_found"},
            {"message", "Could not find a request for the provided nonce."}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        return result_buffer;
    }
    json signable_transfer = requested_transfers[nonce_str];
    requested_transfers.erase(nonce_str);
    Integer stark_key = stark::getStarkPriv(Integer(signable_transfer["eth_address"].get<std::string>().c_str()), Integer(imx_seed_sig_str));
    std::string result = imx_transfers(signable_transfer, stark_key, Integer(imx_transaction_sig_str));
    
    safe_copy_string(result, result_buffer, buffer_size);
    return result_buffer;
}