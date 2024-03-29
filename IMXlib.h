#pragma once
#include "constants.h"
#include "utils.h"
#include "IMXapi.h"
#ifdef IMXLIB_EXPORTS
#include <string>
#include <unordered_map>
#include "ethereum.h"
#include "stark.h"
#include <curl/curl.h>
#include "nlohmann/json.hpp"

#define IMXLIB_API __declspec(dllexport)
#else
#define IMXLIB_API __declspec(dllimport)
#endif

/* Randomly generates a new ethereum private key. */
extern "C" IMXLIB_API char* eth_generate_key(char* result_buffer, int buffer_size);

/* Calculates the ethereum address associated with the given private key. */
extern "C" IMXLIB_API char* eth_get_address(const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Calculate the signature message signed with priv_key, the result is loaded into the char buffer result. */
extern "C" IMXLIB_API char* eth_sign_message(const char* message_str, const char* priv_key, char* result_buffer, int buffer_size);

/* Registers a wallet with IMX. Only needs to be called once, after that the wallet can be used for trading on IMX. */
extern "C" IMXLIB_API char* imx_register_address_presigned(const char* eth_address_str, const char* link_sig_str, const char* seed_sig_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_register_address(const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Attempts to cancel the order with the provided order id on IMX. */
extern "C" IMXLIB_API char* imx_request_cancel_order(const char* order_id_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_finish_cancel_order(const char* order_id_str, const char* eth_address_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_cancel_order(const char* order_id_str, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Returns the minimum fee percentage that needs to be paid when selling the asset provided. Additional fees can be added when creating a sell order with imx_sell_nft. */
extern "C" IMXLIB_API double imx_get_token_trade_fee(const char* token_address_str, const char* token_id_str);

/* Attempts to buy the provided order. If the provided "price_limit" argument is not 0, a check will be made to ensure the total price of the order (including fees) does not exceed the provided limit. */
extern "C" IMXLIB_API char* imx_request_buy_order(const char* order_id_str, const char* eth_address_str, Fee * fees, int fee_count, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_finish_buy_order(const char* nonce_str, double price_limit, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_buy_order(const char* order_id_str, double price_limit, Fee * fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Attempt to create a buy offer on the IMX orderbook. */
extern "C" IMXLIB_API char* imx_request_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* buyer_address_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Attempts to create a sell order on the IMX orderbook. */
extern "C" IMXLIB_API char* imx_request_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* seller_address_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Finish a requested sell order or offer, requires a nonce provided after calling the sell or offer request functions. */
extern "C" IMXLIB_API char* imx_finish_sell_or_offer_nft(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size);

/* Transfers NFTs (ERC721) to a different address. */
extern "C" IMXLIB_API char* imx_request_transfer_nfts(NFT* nfts, int nft_count, const char* receiver_address, const char* sender_address, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_request_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size);

extern "C" IMXLIB_API char* imx_transfer_nfts(NFT* nfts, int nft_count, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Transfers tokens (ETH or ERC20) to a different address. */
extern "C" IMXLIB_API char* imx_request_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size);
extern "C" IMXLIB_API char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size);

/* Finish a requested transfer for NFTs or other tokens, requires a nonce provided after calling one of the transfer request functions. */
extern "C" IMXLIB_API char* imx_finish_transfer(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size);