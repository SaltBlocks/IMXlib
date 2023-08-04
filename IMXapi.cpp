#include "pch.h"
#include "IMXapi.h"

std::string imx_signable_cancel_order_details(int order_id, CURL* curl)
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
std::string imx_delete_order(int order_id, CryptoPP::Integer eth_address, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl)
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
std::string imx_signable_trade_details(unsigned long long order_id_str, const char* eth_address, nlohmann::json fee_data, CURL* curl)
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
std::string imx_trades(nlohmann::json signable_order, double price_limit, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl)
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
std::string imx_signable_order_details(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, nlohmann::json fee_data, const char* seller_address_str, CURL* curl)
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
std::string imx_orders(nlohmann::json signable_order, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl)
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
std::string imx_signable_transfer_details(nlohmann::json signable_requests, const char* sender_address_str, CURL* curl)
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
std::string imx_transfers(nlohmann::json signable_responses, CryptoPP::Integer stark_key, CryptoPP::Integer imx_signature, CURL* curl)
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