#include "pch.h"
#include "IMXlib.h"

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

char* eth_sign_message(const char* message, const char* priv_key, char* result, int resultSize)
{
	/* Define components of CryptoPP we're using for ease of use. */
	using CryptoPP::Integer;
	using CryptoPP::byte;
	using namespace std;

	/* Convert the private key string to an integer. */
	Integer priv(priv_key);

	/* Calculate the signature and store in a string. */
	Integer sig = ethereum::signMessage(message, priv);
	byte sigBytes[32];
	sig.Encode(sigBytes, 32);
	string sig_str = binToHexStr(sigBytes, 32);

	/* Copy the signature into the provided output. */
	safe_copy_string(sig_str, result, resultSize);

	/* Return the output. */
	return result;
}

char* imx_cancel_order(const char* order_id_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create json string for requesting order deletion details. */
    json details = { { "order_id", std::stoi(order_id_str) } };
    std::string details_str = details.dump();

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    CURL* curl;
    curl = curl_easy_init();
    std::string response_string;
    std::string header_string;
    setupCURL(curl, "https://api.x.immutable.com/v1/signable-cancel-order-details", "POST", headers, details_str.c_str(), response_string, header_string);

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
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }
    
    /* The request succeeded, check if it contained the requested data, otherwise return this data as error. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the deletion request. */
    std::string sign_str = response_data["signable_message"].get<std::string>();

    /* Sign the transaction with the user's STARK private key and the submit message using the ethereum private key. */
    Integer eth_priv = Integer(eth_priv_str);
    Integer stark_priv = stark::getStarkPriv(eth_priv);
    byte cancel_sign[64];
    stark::signHash(stark::getCancelHash(Integer(order_id_str)), stark_priv).Encode(cancel_sign, 64);
    byte eth_address[20];
    ethereum::getAddress(eth_priv).Encode(eth_address, 20);
    byte eth_sign[65];
    ethereum::signMessage(sign_str, eth_priv).Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Transform the signatures to strings we can pass to IMX. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += binToHexStr(eth_address, 20);
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);
    json cancelData = {
        {"stark_signature", binToHexStr(cancel_sign, 64)}
    };
    std::string cancelStr = cancelData.dump();

    /* Create the URL that we can contact to execute the order deletion request. */
    std::string cancel_url = "https://api.x.immutable.com/v1/orders/";
    cancel_url += order_id_str;

    /* Update the headers to include the message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Setup the details for the deletion request. */
    response_string.clear();
    header_string.clear();
    setupCURL(curl, cancel_url.c_str(), "DELETE", headers, cancelStr.c_str(), response_string, header_string);

    /* Execute the request and cleanup CURL. */
    con = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    /* Copy and return the result */
    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

int imx_get_token_trade_fee(const char* token_address_str, const char* token_id, CURL* curl)
{
    using json = nlohmann::json;

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Create the URL for getting the fee amounts. */
    std::stringstream ss;
    ss << "https://api.x.immutable.com/v1/assets/" << token_address_str << "/" << token_id << "?include_fees=true";
    std::string fee_url = ss.str();
    
    /* Setup url and data to send. */
    bool do_cleanup = false;
    if (curl == NULL)
    {
        curl = curl_easy_init();
        do_cleanup = true;
    }
    std::string response_string;
    std::string header_string;
    setupCURL(curl, fee_url, "GET", headers, NULL, response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Cleanup curl*/
    if (do_cleanup)
    {
        curl_easy_cleanup(curl);
    }

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
    return fee_percentage + 1; // Add the 1% marketplace maker fee.
}

char* imx_buy_nft(unsigned long long order_id, const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Get the public address of the user. */
    Integer address = ethereum::getAddress(Integer(eth_priv_str));
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    /* Convert the provided price into a string in the proper format for submitting to IMX. */
    price *= 10000000000;
    unsigned long long amountULL = static_cast<unsigned long long>(price);
    std::stringstream ss;
    ss << std::dec << amountULL << "00000000";
    std::string amount_str = ss.str();

    /* Format the json for the token we are looking to spend, if this starts with 0x we'll assume it is an ERC20 token and the token address was provided. */
    json token_data;
    if (!strncmp(token_id_str, "0x", 2))
    {
        token_data = {
            { "data", {
                { "decimals", 18},
                { "token_address", token_id_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", 18}}},
            { "type", token_id_str}
        };
    }

    /* Construct the json for the fees that should be applied, start with the taker marketplace fee and add additional fees as provided by the user. */
    CryptoPP::byte market_bytes[20];
    stark::getMarketFeeAddress(market_bytes);
    json fee_data = {
            {
                { "address", binToHexStr(market_bytes, 20)}, // Maker marketplace fee of 1%
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

    json request_data = {
        { "token_buy", {
            { "data", {
                { "token_address", nft_address_str },
                { "token_id", nft_id_str }
            }},
            { "type", "ERC721" }
            }
        },
        { "token_sell", token_data },
        { "amount_buy", "1" },
        { "amount_sell", amount_str },
        { "include_fees", true },
        { "fees", fee_data },
        { "user", address_str }
    };
    std::string request_str = request_data.dump();

    /* Create CURL instance. */
    CURL* curl;
    curl = curl_easy_init();

    /* URL for requesting the signable order. */
    std::string request_url = "https://api.x.immutable.com/v1/signable-order-details";

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    std::string response_string;
    std::string header_string;
    setupCURL(curl, request_url, "POST", headers, request_str.c_str(), response_string, header_string);

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
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    std::string sign_str = response_data["signable_message"].get<std::string>();

    /* Sign the message. */
    Integer eth_priv = Integer(eth_priv_str);
    byte eth_sign[65];
    ethereum::signMessage(sign_str, eth_priv).Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Collect all data needed to sign the transaction. */
#pragma warning( push )
#pragma warning( disable : 4244)
    Integer vault_sell = response_data["vault_id_sell"].get<__int64>();
    Integer vault_buy = response_data["vault_id_buy"].get<__int64>();
    Integer amount_sell(response_data["amount_sell"].get<std::string>().c_str());
    Integer amount_buy(response_data["amount_buy"].get<std::string>().c_str());
    Integer token_sell(response_data["asset_id_sell"].get<std::string>().c_str());
    Integer token_buy(response_data["asset_id_buy"].get<std::string>().c_str());
    Integer nonce = response_data["nonce"].get<__int64>();
    Integer expiration_timestamp = response_data["expiration_timestamp"].get<__int64>();
    Integer token_fee(response_data["fee_info"]["asset_id"].get<std::string>().c_str());
    Integer vault_fee = response_data["fee_info"]["source_vault_id"].get<__int64>();
    Integer fee_limit(response_data["fee_info"]["fee_limit"].get<std::string>().c_str());
#pragma warning( pop )

    /* Create the order hash and sign it. */
    Integer order_hash = stark::getOrderHash(vault_sell, vault_buy, amount_sell, amount_buy, token_sell, token_buy, nonce, expiration_timestamp, token_fee, vault_fee, fee_limit);
    Integer stark_sign = stark::signHash(order_hash, stark::getStarkPriv(eth_priv));

    /* Encode the signature into a string. */
    byte stark_sign_bytes[64];
    stark_sign.Encode(stark_sign_bytes, 64);
    std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

    /* Properly format the signed order. */
    json trade_data = {
        { "stark_key", response_data["stark_key"] },
        { "amount_sell", response_data["amount_sell"] },
        { "asset_id_sell", response_data["asset_id_sell"] },
        { "vault_id_sell", response_data["vault_id_sell"] },
        { "amount_buy", response_data["amount_buy"] },
        { "asset_id_buy", response_data["asset_id_buy"] },
        { "vault_id_buy", response_data["vault_id_buy"] },
        { "expiration_timestamp", response_data["expiration_timestamp"] },
        { "nonce", response_data["nonce"] },
        { "stark_signature", stark_signature },
        { "order_id", order_id },
        { "fee_info", response_data["fee_info"]},
        { "include_fees", true },
        { "fees", fee_data }
    };
    std::string trade_str = trade_data.dump();

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += address_str;
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);

    /* Update the headers to include the address and message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Prepare to submit the signed order. */
    std::string submit_url = "https://api.x.immutable.com/v1/trades";
    response_string.clear();
    header_string.clear();
    setupCURL(curl, submit_url, "POST", headers, trade_str.c_str(), response_string, header_string);

    /* Perform web request. */
    con = curl_easy_perform(curl);

    /* Cleanup curl*/
    curl_easy_cleanup(curl);

    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Get the public address of the user. */
    Integer address = ethereum::getAddress(Integer(eth_priv_str));
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    /* Get the fee percentage that needs to be added. */

    /* Create CURL instance. */
    CURL* curl;
    curl = curl_easy_init();

    /* First get the base fee percentage (2% protocol, 1% maker, x% royalty) */
    int fee_percentage = imx_get_token_trade_fee(nft_address_str, nft_id_str, curl);

    /* If an error occurred, fee_percentage will be -1, check if this is the case*/
    if (fee_percentage == -1)
    {
        json errorRes = {
            {"code", "invalid_fee"},
            {"message", "Failed to get the fee percentage associated with this asset."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Loop through the user added fees and add these to the total*/
    if (fees == NULL)
    {
        fee_count = 0; // if fees is Null, never try to add user fees.
    }
    for (int i = 0; i < fee_count; i++)
    {
        fee_percentage += fees[i].percentage;
    }

    /* Make sure the price is within the bounds. */
    unsigned long long max_price = ULLONG_MAX / (100 + fee_percentage) / 100000000;

    if (price >= max_price || price <= 0)
    {
        json errorRes = {
            {"code", "invalid_data"},
            {"message", "The offer price was lower than 0 or exceeded the maximum offer price that can be submitted to IMX."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Convert the provided price into a string in the proper format for submitting to IMX. */
    price *= 100000000;
    unsigned long long priceULL = static_cast<unsigned long long>(price);
    priceULL *= (100 + fee_percentage);
    std::stringstream ss;
    ss << std::dec << priceULL << "00000000";
    std::string price_str = ss.str();

    /* Format the json for the token we are looking to receive, if this starts with 0x we'll assume it is an ERC20 token and the token address was provided. */
    json token_data;
    if (!strncmp(token_id_str, "0x", 2))
    {
        token_data = {
            { "data", {
                { "decimals", 18},
                { "token_address", token_id_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", 18}}},
            { "type", token_id_str}
        };
    }

    /* Construct the json for the fees that should be applied, start with the maker marketplace fee and add additional fees as provided by the user. */
    CryptoPP::byte market_bytes[20];
    stark::getMarketFeeAddress(market_bytes);
    json fee_data = {
            {
                { "address", binToHexStr(market_bytes, 20)}, // Maker marketplace fee of 1%
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
        { "include_fees", true },
        { "user", address_str}
    };
    std::string req = request_data.dump();

    /* URL for requesting the signable order. */
    std::string request_url = "https://api.x.immutable.com/v1/signable-order-details";

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
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }
    
    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    std::string sign_str = response_data["signable_message"].get<std::string>();

    /* Sign the message. */
    Integer eth_priv = Integer(eth_priv_str);
    byte eth_sign[65];
    ethereum::signMessage(sign_str, eth_priv).Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Collect all data needed to sign the transaction. */
#pragma warning( push )
#pragma warning( disable : 4244)
    Integer vault_sell = response_data["vault_id_sell"].get<__int64>();
    Integer vault_buy = response_data["vault_id_buy"].get<__int64>();
    Integer amount_sell(response_data["amount_sell"].get<std::string>().c_str());
    Integer amount_buy(response_data["amount_buy"].get<std::string>().c_str());
    Integer token_sell(response_data["asset_id_sell"].get<std::string>().c_str());
    Integer token_buy(response_data["asset_id_buy"].get<std::string>().c_str());
    Integer nonce = response_data["nonce"].get<__int64>();
    Integer expiration_timestamp = response_data["expiration_timestamp"].get<__int64>();
#pragma warning( pop )
    
    /* Create the order hash and sign it. */
    Integer order_hash = stark::getOrderHash(vault_sell, vault_buy, amount_sell, amount_buy, token_sell, token_buy, nonce, expiration_timestamp);
    Integer stark_sign = stark::signHash(order_hash, stark::getStarkPriv(eth_priv));

    /* Encode the signature into a string. */
    byte stark_sign_bytes[64];
    stark_sign.Encode(stark_sign_bytes, 64);
    std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

    /* Properly format the signed order. */
    json order_data = {
        { "stark_key", response_data["stark_key"] },
        { "amount_sell", response_data["amount_sell"] },
        { "asset_id_sell", response_data["asset_id_sell"] },
        { "vault_id_sell", response_data["vault_id_sell"] },
        { "amount_buy", response_data["amount_buy"] },
        { "asset_id_buy", response_data["asset_id_buy"] },
        { "vault_id_buy", response_data["vault_id_buy"] },
        { "expiration_timestamp", response_data["expiration_timestamp"] },
        { "nonce", response_data["nonce"] },
        { "stark_signature", stark_signature },
        { "include_fees", true },
        { "fees", fee_data }
    };
    std::string order_str = order_data.dump();

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += address_str;
    std::string msgEthSign = "x-imx-eth-signature: ";
    msgEthSign += binToHexStr(eth_sign, 65);

    /* Update the headers to include the address and message signature. */
    headers = curl_slist_append(headers, msgAddress.c_str());
    headers = curl_slist_append(headers, msgEthSign.c_str());

    /* Prepare to submit the signed order. */
    std::string submit_url = "https://api.x.immutable.com/v1/orders";
    response_string.clear();
    header_string.clear();
    setupCURL(curl, submit_url, "POST", headers, order_str.c_str(), response_string, header_string);

    /* Perform web request. */
    con = curl_easy_perform(curl);

    /* Cleanup curl*/
    curl_easy_cleanup(curl);

    /* Copy and return the result */
    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_transfer(nlohmann::json token_json, const char* token_amount, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Get the public address of the user. */
    Integer address = ethereum::getAddress(Integer(eth_priv_str));
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    /* Create CURL instance. */
    CURL* curl;
    curl = curl_easy_init();

    /* Create the json string for requesting the order we can sign. */
    json request_data = {
        { "sender_ether_key", address_str},
        { "signable_requests", {
            {
                { "amount", token_amount},
                { "receiver", receiver_address },
                { "token", token_json }
            }
            }
        }
    };
    std::string request_str = request_data.dump();

    /* Define Header. */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Setup url and data to send. */
    std::string response_string;
    std::string header_string;
    setupCURL(curl, "https://api.x.immutable.com/v2/signable-transfer-details", "POST", headers, request_str.c_str(), response_string, header_string);

    /* Perform web request. */
    int con = curl_easy_perform(curl);

    /* Check if the connection itself failed. */
    if (con != 0)
    {
        json errorRes = {
            {"code", "failed_to_connect_to_server"},
            {"message", "Failed to connect to IMX, check your internet connection."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    std::string sign_str = response_data["signable_message"].get<std::string>();

    /* Sign the message. */
    Integer eth_priv = Integer(eth_priv_str);
    byte eth_sign[65];
    ethereum::signMessage(sign_str, eth_priv).Encode(eth_sign, 65);
    eth_sign[64] %= 27;

    /* Collect all data needed to sign the transaction. */
#pragma warning( push )
#pragma warning( disable : 4244)
    Integer amount(response_data["signable_responses"][0]["amount"].get<std::string>().c_str());
    if (amount != 1)
    {
        /* 
            The amount used to generate the signature hash when transfering a token (ETH/ERC20) needs to be divided by 10 ^ 8 to get a valid result. 
            I'm guessing this is for compatibility purposes with a JS library but not entirely sure.
        */
        amount /= 100000000;
    }
    Integer nonce = response_data["signable_responses"][0]["nonce"].get<__int64>();
    Integer sender_vault_id = response_data["signable_responses"][0]["sender_vault_id"].get<__int64>();
    Integer token(response_data["signable_responses"][0]["asset_id"].get<std::string>().c_str());
    Integer receiver_vault_id = response_data["signable_responses"][0]["receiver_vault_id"].get<__int64>();
    Integer receiver_public_key(response_data["signable_responses"][0]["receiver_stark_key"].get<std::string>().c_str());
    Integer expiration_timestamp = response_data["signable_responses"][0]["expiration_timestamp"].get<__int64>();
#pragma warning( pop )

    /* Create the transfer hash and sign it. */
    Integer transfer_hash = stark::getTransferHash(amount, nonce, sender_vault_id, token, receiver_vault_id, receiver_public_key, expiration_timestamp);
    Integer stark_sign = stark::signHash(transfer_hash, stark::getStarkPriv(eth_priv));

    /* Encode the signature into a string. */
    byte stark_sign_bytes[64];
    stark_sign.Encode(stark_sign_bytes, 64);
    std::string stark_signature = binToHexStr(stark_sign_bytes, 64);

    /* Properly format the signed order. */
    json transfer_data = {
        { "sender_stark_key", response_data["sender_stark_key"] },
        { "requests", {
            {
                { "receiver_stark_key", response_data["signable_responses"][0]["receiver_stark_key"] },
                { "receiver_vault_id", response_data["signable_responses"][0]["receiver_vault_id"] },
                { "amount", response_data["signable_responses"][0]["amount"] },
                { "asset_id", response_data["signable_responses"][0]["asset_id"] },
                { "expiration_timestamp", response_data["signable_responses"][0]["expiration_timestamp"] },
                { "nonce", response_data["signable_responses"][0]["nonce"] },
                { "sender_vault_id", response_data["signable_responses"][0]["sender_vault_id"] },
                { "stark_signature", stark_signature }
            }
            }
        }
    };
    std::string transfer_str = transfer_data.dump();

    /* Transform the eth address and message signature to strings we can pass to IMX in the header. Otherwise, the order will be rejected even with a valid stark signature. */
    std::string msgAddress = "x-imx-eth-address: ";
    msgAddress += address_str;
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
    con = curl_easy_perform(curl);

    /* Cleanup curl*/
    curl_easy_cleanup(curl);

    /* Copy and return the result */
    safe_copy_string(response_string, result_buffer, buffer_size);
    return result_buffer;
}

char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    
    /* Create the json containing the token data for the nft. */
    json token_data = {
            { "type", "ERC721" },
            { "data", {
                { "token_id", nft_id_str },
                { "token_address", nft_address_str }
                }
            }
        };

    /* Transfer the token. */
    return imx_transfer(token_data, "1", receiver_address, eth_priv_str, result_buffer, buffer_size);
}

char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;

    /* Make sure the price is within the bounds. */
    unsigned long long max_amount = ULLONG_MAX / 10000000000;

    if (amount >= max_amount || amount <= 0)
    {
        json errorRes = {
            {"code", "invalid_data"},
            {"message", "The offer price was lower than 0 or exceeded the maximum offer price that can be submitted to IMX."}
        };
        std::string errorStr = errorRes.dump();
        safe_copy_string(errorStr, result_buffer, buffer_size);
        return result_buffer;
    }

    /* Create the json containing the token data for the nft. */
    json token_data;
    if (!strncmp(token_id_str, "0x", 2))
    {
        token_data = {
            { "data", {
                { "decimals", 18},
                { "token_address", token_id_str}
                }
            },
            { "type", "ERC20"}
        };
    }
    else
    {
        token_data = {
            { "data", {{"decimals", 18}}},
            { "type", token_id_str}
        };
    }

    /* Convert the provided price into a string in the proper format for submitting to IMX. */
    amount *= 10000000000;
    unsigned long long amountULL = static_cast<unsigned long long>(amount);
    std::stringstream ss;
    ss << std::dec << amountULL << "00000000";
    std::string amount_str = ss.str();

    /* Transfer the token. */
    return imx_transfer(token_data, amount_str.c_str(), receiver_address, eth_priv_str, result_buffer, buffer_size);
}