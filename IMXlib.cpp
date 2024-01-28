#include "pch.h"
#include "IMXlib.h"

// Storage for requested orders.
std::unordered_map<std::string, nlohmann::json> requested_buys;
std::unordered_map<std::string, nlohmann::json> requested_sales;
std::unordered_map<std::string, nlohmann::json> requested_transfers;

// Track if the existence of the stark_curve file containing the ECDSA parameters needed for signing transactions has been checked.
static bool stark_curve_checked = false;

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

double imx_get_token_trade_fee(const char* token_address_str, const char* token_id_str)
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
        return -1.; // return error
    }
    /* Calculate the base fee percentage. */
    json fee_data = data["fees"];
    double fee_percentage = 0.;
    for (int i = 0; i < fee_data.size(); i++)
    {
        fee_percentage += fee_data[i]["percentage"].get<double>();
    }
    return fee_percentage; // Most marketplaces will add a 1% taker fee to this percentage, this also excludes the maker marketplace fee.
}

char* imx_request_buy_order(const char* order_id_str, const char* eth_address_str, Fee* fees, int fee_count, char* result_buffer, int buffer_size)
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

char* imx_finish_buy_order(const char* nonce_str, double price_limit, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

char* imx_buy_order(const char* order_id_str, double price_limit, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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
        curl_easy_cleanup(curl); // Cleanup CURL.
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

char* imx_request_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* buyer_address_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    json fee_json = imx_get_fee_json(fees, fee_count);
    std::string response_string = imx_signable_order_details(nft_address_str, nft_id_str, true, imx_token_details(token_id_str, curl), price, fee_json, buyer_address_str, curl);

    /* Cleanup CURL. */
    curl_easy_cleanup(curl);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message") || !response_data.contains("nonce"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }
    if (!response_data.contains("fee_info")) // This sometimes happens if you try to create an offer for an asset that's not on sale.
    {
        json errorRes = {
            {"code", "bad_request"},
            {"message", "not allowed to create a buy order for an asset without a matching listing (sell order)"}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    /* Extract the message that we need to sign to submit the order. */
    response_data["eth_address"] = buyer_address_str;
    response_data["fee_json"] = fee_json;
    requested_sales.insert(std::pair<std::string, json>(std::to_string(response_data["nonce"].get<__int64>()), response_data));
    json result = {
            {"nonce", response_data["nonce"].get<__int64>()},
            {"signable_message", response_data["signable_message"].get<std::string>()}
    };

    safe_copy_string(result.dump(), result_buffer, buffer_size);
    return result_buffer;
}

char* imx_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }
    
    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    json fee_json = imx_get_fee_json(fees, fee_count);
    json response_data = json::parse(imx_signable_order_details(nft_address_str, nft_id_str, true, imx_token_details(token_id_str, curl), price, fee_json, address_str.c_str(), curl));
    
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_data.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }
    if (!response_data.contains("fee_info")) // This sometimes happens if you try to create an offer for an asset that's not on sale.
    {
        json errorRes = {
            {"code", "bad_request"},
            {"message", "not allowed to create a buy order for an asset without a matching listing (sell order)"}
        };
        safe_copy_string(errorRes.dump(), result_buffer, buffer_size);
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

char* imx_request_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* seller_address_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    json fee_json = imx_get_fee_json(fees, fee_count);
    std::string response_string = imx_signable_order_details(nft_address_str, nft_id_str, false, imx_token_details(token_id_str, curl), price, fee_json, seller_address_str, curl);
    
    /* Cleanup CURL. */
    curl_easy_cleanup(curl);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message") || !response_data.contains("nonce"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
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
    return result_buffer;
}

char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    /* Get the public address of the user. */
    Integer eth_priv(eth_priv_str);
    Integer address = ethereum::getAddress(eth_priv);
    byte addressBytes[20];
    address.Encode(addressBytes, 20);
    std::string address_str = binToHexStr(addressBytes, 20);

    json fee_json = imx_get_fee_json(fees, fee_count);
    json response_data = json::parse(imx_signable_order_details(nft_address_str, nft_id_str, false, imx_token_details(token_id_str, curl), price, fee_json, address_str.c_str(), curl));

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

char* imx_finish_sell_or_offer_nft(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
{
    using json = nlohmann::json;
    using CryptoPP::Integer;
    using CryptoPP::byte;

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    json token_details = imx_token_details(token_id_str, curl);
    if (token_details.contains("code"))
    {
        safe_copy_string(token_details.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    json transfer_data = imx_get_send_token_json(token_details, amount, receiver_address_str);
    if (transfer_data.contains("code"))
    {
        safe_copy_string(transfer_data.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    std::string response_string = imx_signable_transfer_details(transfer_data, sender_address_str, curl);

    /* Cleanup CURL. */
    curl_easy_cleanup(curl);

    /* Check if we got the correct response data. Otherwise, return the error given by IMX. */
    json response_data = json::parse(response_string);
    if (!response_data.contains("signable_message"))
    {
        safe_copy_string(response_string, result_buffer, buffer_size);
        return result_buffer;
    }

    response_data["eth_address"] = sender_address_str;
    response_data["signable_responses"][0]["quantum"] = token_details["quantum"];
    
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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

    /* Create CURL instance. */
    CURL* curl = curl_easy_init();

    json token_details = imx_token_details(token_id_str, curl);
    if (token_details.contains("code"))
    {
        safe_copy_string(token_details.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

    json transfer_data = imx_get_send_token_json(token_details, amount, receiver_address_str);
    if (transfer_data.contains("code"))
    {
        safe_copy_string(transfer_data.dump(), result_buffer, buffer_size);
        curl_easy_cleanup(curl); // Cleanup CURL.
        return result_buffer;
    }

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
    response_data["signable_responses"][0]["quantum"] = token_details["quantum"];

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

    /* Make sure we have access to the stark ECDSA curve needed to sign this transaction. */
    if (!stark_curve_checked) {
        if (!checkCurveFile(result_buffer, buffer_size))
        {
            return result_buffer;
        }
        stark_curve_checked = true;
    }

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