# IMXlib

Unofficial library for interacting with IMX.\
I'll add links to some example projects using this library here in the coming weeks:\
Command line marketplace for Gods Unchained written in python: [py-gods-unchained-market](https://github.com/SaltBlocks/py-gods-unchained-market)

## Usage
Binaries for use on 32 and 64-bit windows can be found in the releases section.
Exported functions and constants can be found in IMXlib.h and are implemented in IMXlib.cpp and constants.cpp.
Sections below cover the exported functions and how to use them.\
\
The easiest way to use this project is to download the example visual studio project from the [releases section](https://github.com/SaltBlocks/IMXlib/releases). This can also be downloaded directly [here](https://github.com/SaltBlocks/IMXlib/releases/download/v2.0/IMXlib.v2.0.visual.studio.project.zip).
If you have visual studio installed and properly setup to compile c++ programs, this project should compile straight away without having to change any settings. The example program is dynamically linked to IMXlib and curl. It can use all the functions covered below. By default it will generate a new ethereum private key and print that together with the address and the signature for the string "Hello World!" every time it is run. 

Starting from version 2.1, the library is dynamically linked and thus requires the [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170) (Download: [x64](https://aka.ms/vs/17/release/vc_redist.x64.exe)/[x86](https://aka.ms/vs/17/release/vc_redist.x86.exe)) to be installed in order to run.\
In all likelihood, you won't have to download this as you'll allready have it installed.

## Ethereum functions

### eth_generate_key
```c
char* eth_generate_key(char* result_buffer, int buffer_size)
```
Generate a random valid private key on the secp256k1 curve. The generated key is stored as a hexstring in the result_buffer. The buffer_size parameter is used to pass along the size of this buffer. Data is never written to the buffer past the provided buffer size. Ethereum keys have a length of 32 bytes. When converted into a hexstring, 67 characters are required. (2 characters per byte, 2 characters for the "0x" prefix and one for the null terminator) 
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char key[67];
    std::cout << eth_generate_key(key, 67) << std::endl;
}
```
output (will be different every time):
```
0xabf5a39b223e1b3261f0128c1d575c5b39b865192c55faf60a9a36df77ed97ca
```

### eth_get_address
```c
char* eth_get_address(const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Calculate the ethereum address associated with the provided private key. The address is stored as a hexstring in the result_buffer. The buffer_size parameter is used to pass along the size of this buffer. Data is never written to the buffer past the provided buffer size. Ethereum addresses have a size of 20 bytes. When converted into a hexstring, 43 characters are required. (2 characters per byte, 2 characters for the "0x" prefix and one for the null terminator)
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[67] = "0xabf5a39b223e1b3261f0128c1d575c5b39b865192c55faf60a9a36df77ed97ca";
    char address[43];
    std::cout << eth_get_address(key, address, 43) << std::endl;
}
```
output:
```
0x3d248e3370bc947b8d225a680d0e4f57aba9640f
```
### eth_sign_message
```c
char* eth_sign_message(const char* message, const char* priv_key, char* result_buffer, int buffer_size)
```
Sign the message string using the provided private key and store the result in the result_buffer.  Data is never written to the buffer past the provided buffer size. Ethereum signatures have a size of 65 bytes. The first 64 bytes contain the ECDSA signature (r, s), the last byte contains the recovery ID (v). Without the recovery ID the signature could possible belong to two different addresses. The generated signatures are deterministic and are generated according to the RFC6979 standard. When converted into a hexstring, 133 characters are required. (2 characters per byte, 2 characters for the "0x" prefix and one for the null terminator)
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[67] = "0xabf5a39b223e1b3261f0128c1d575c5b39b865192c55faf60a9a36df77ed97ca";
    const char message[13] = "Hello World!";
    char signature[133];
    std::cout << eth_sign_message(message, key, signature, 133) << std::endl;
}
```
output:
```
0x6099ec4a1b4363cf9aeb4954fcd3911cec4eef9dc03249e09dfb9b5964e9ea6675a48b16e29b2f73629c648173e9895d4ebdd1603bf7187a396208bbee11dbf41b
```
## IMX functions

### imx_register_address
```c
char* imx_register_address(const char* eth_priv_str, char* result_buffer, int buffer_size)
```
In order to trade on IMX using an ethereum address, it needs to be registered and linked with the corresponding wallet on IMX. This normally happens on the *"Set up Immutable X Key"* screen the first time you connect to your wallet on the IMX website. This function registers the wallet and stores the server response in the result_buffer. If the response is longer than the buffer_size, the remaining characters are discarded. The example shows a successful result.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[67] = "0xabf5a39b223e1b3261f0128c1d575c5b39b865192c55faf60a9a36df77ed97ca";
    char response[1000];
    std::cout << imx_register_address(key, response, 1000) << std::endl;
}
```
output:
```
{"tx_hash":""}
```

### imx_register_address_presign
```c
char* imx_register_address_presigned(const char* eth_address_str, const char* link_sig_str, const char* seed_sig_str, char* result_buffer, int buffer_size)
```
In case a hardware wallet is used it is impossible to pass the ethereum private key to the library function. In this case, we can presign the linking messages and pass the signatures to IMXlib instead.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[67] = "0xabf5a39b223e1b3261f0128c1d575c5b39b865192c55faf60a9a36df77ed97ca";
    char address[43];
    char link_signature[133];
    char imx_seed[133];
    char response[1000];

    eth_get_address(key, address, 43);
    
    // Generate the signatures we need to link the wallet. This could for example be done externally using a hardware wallet. For the example we just use IMXlib.
    eth_sign_message(imx_link_message, key, link_signature, 133); // The ETH signature for the message "Only sign this key linking request from Immutable X"
    eth_sign_message(imx_seed_message, key, imx_seed, 133); // The ETH signature for the message "Only sign this request if you’ve initiated an action with Immutable X.".

    std::cout << imx_register_address_presigned(address, link_signature, imx_seed, response, 1000) << std::endl;
}
```

### imx_cancel_order
```c
char* imx_cancel_order(const char* order_id_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Cancels an order placed by the wallet corresponding to the provided private key currently on IMX. The order id corresponding to a specific order can be found using the IMX api. You can check the [api reference here](https://docs.x.immutable.com/reference#/operations/listAssets). The server response is stored in the result_buffer. If the response is longer than the buffer_size, the remaining characters are discarded. The example shows a successful result.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[] = "" // private key goes here, like in previous functions.
    const char order_id[] = "243671998" // order_id can be retrieved using the imx api.
    char response[1000];
    std::cout << imx_cancel_order(order_id, key, response, 1000) << std::endl;
}
```
output:
```
{"order_id":243671998,"status":""}
```
### imx_request_cancel_order
```c
char* imx_request_cancel_order(const char* order_id_str, char* result_buffer, int buffer_size)
```
Fetches the message from IMX that needs to be signed using the ethereum private key to cancel the order corresponding to the provided order_id.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char order_id[] = "313739468"; // order_id can be retrieved using the imx api.
    char response[1000];
    std::cout << imx_request_cancel_order(order_id, response, 1000) << std::endl;
}
```
output:
```
Only sign this request if you’ve initiated an action with Immutable X.

For internal use:
22f8f8a238082c33090ae1039d502f1e668235eec84de84bfbb0757738e1ba53
```
### imx_finish_cancel_order
```c
char* imx_finish_cancel_order(const char* order_id_str, const char* eth_address_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size);
```
Cancels the order corresponding to the provided order_id_str using the provided signatures. Requires the signature hash of "Only sign this request if you’ve initiated an action with Immutable X." to be passed to imx_seed_sig_str and the signature hash of the message obtained from imx_request_cancel_order to be passed to imx_transaction_sig_str.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char order_id[] = "313739468"; // order_id can be retrieved using the imx api.
    char response[1000];
    imx_request_cancel_order(order_id, response, 1000);
    
    const char key[] = ""; // private key goes here, like in previous functions.
    char address[43];
    char imx_cancel_sig[133];
    char imx_seed[133];
    eth_get_address(key, address, 43);
    eth_sign_message(response, key, imx_cancel_sig, 133); // The ETH signature for the message returned by imx_request_cancel_order.
    eth_sign_message(imx_seed_message, key, imx_seed, 133); // The ETH signature for the message "Only sign this request if you’ve initiated an action with Immutable X.".

    std::cout << imx_finish_cancel_order(order_id, address, imx_seed, imx_cancel_sig, response, 1000);
}
```
output:
```
{"order_id":313739468,"status":""}
```
### imx_get_token_trade_fee
```c
double imx_get_token_trade_fee(const char* token_address_str, const char* token_id_str)
```
Gets the fee percentage that is added when selling this card on the IMX platform. The fee includes the protocol and royalty fees. Marketplace fees are not included as these aren't known but this will in most cases add at least 1% more to the buy price.
The token_address is the same for all assets in the collection it is part of. Both the collection address and token id can be found either using the imx api and are also listed on [immutascan](https://immutascan.io/). You can find the card from the example on immutascan [here](https://immutascan.io/address/0xacb3c6a43d15b907e8433077b6d38ae40936fe2c/211653036). The function returns the fee percentage as a double.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char collection_address[] = "0xacb3c6a43d15b907e8433077b6d38ae40936fe2c"; // Address for gods unchained cards.
    const char token_id[] = "211653036"; // This token ID belongs to an "Aetheric Repulsor" card.
    char response[1000];
    std::cout << imx_get_token_trade_fee(collection_address, token_id) << std::endl;
}
```
### imx_buy_nft
```c
char* imx_buy_nft(const char* order_id_str, double price_limit, Fee * fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Buys the provided order using the wallet corresponding to the provided private key. The order_id can be retrieved from orders found using the [imx api](https://docs.x.immutable.com/x/reference/#/operations/listOrdersV3). The token_id is the token_address of the asset you are spending (can be found in the order) or simply "ETH" if you are buying using ethereum. The price variable should be equal or greater than the price you will be paying including all fees. If it lower than the actual price, an error message will be returned.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[] = ""; // private key goes here, like in previous functions.
    char response[1000];
    Fee user_fee = { "0x216df17ec98bae6047f2c5466162333f1aee23dc", 1 }; // Add a 1% fee to this order paid out to 0x216df17ec98bae6047f2c5466162333f1aee23dc.
    std::cout << imx_buy_nft("313603208", 0.000035, &user_fee, 1, key, response, 1000) << std::endl; // Attempts to buy order with id 313603208 for at most 0.000035 of the buy currency (ETH)
}
```
output:
```
{"trade_id":235339726,"status":""}
```
### imx_request_buy_nft
```c
char* imx_request_buy_nft(const char* order_id_str, const char* eth_address_str, Fee * fees, int fee_count, char* result_buffer, int buffer_size);
```
Prepares to buy the provided order and returns the message that needs to be signed using the users private key to continue with the buy. Also returns a nonce that can be used with the imx_finish_buy_nft function to finish buying the order once the message is signed.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    std::cout << imx_request_buy_nft("313751181", address, NULL, 0, response, 1000) << std::endl; // Request to buy order with id 313751181.
}
```
output:
```c
{"nonce":2085808257,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n011eb1243e49ff17d501fab0e816c0c2848d6684128568e79632a0c584f449fb"}
```
### imx_finish_buy_nft
```c
char* imx_finish_buy_nft(const char* nonce_str, double price_limit, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
```
Finish a requested buy order. Used to complete orders that need to be signed externally due to the private key not being available. (for example in case a hardware wallet is used).
#### Example
```c
#include <iostream>
#include <string>
#include "IMXlib.h"
#include "nlohmann/json.hpp"

int main()
{
    using nlohmann::json;
    char private_key[67] = ""; // private key goes here, like in previous functions.
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    imx_request_buy_nft("313751181", address, NULL, 0, response, 1000); // Request to buy order with id 313751181.
    
    json response_data = json::parse(response); // Parse the response.
    std::string nonce = std::to_string(response_data["nonce"].get<__int64>());
    std::string message = response_data["signable_message"].get<std::string>();
    
    char imx_seed_sig[133];
    char imx_transaction_sig[133];
    eth_sign_message(imx_seed_message, private_key, imx_seed_sig, 133); // Calculate the stark key seed used for signing on IMX.
    eth_sign_message(message.c_str(), private_key, imx_transaction_sig, 133); // Calculate the transaction signature.

    std::cout << imx_finish_buy_nft(nonce.c_str(), 0.000035, imx_seed_sig, imx_transaction_sig, response, 1000) << std::endl;
}
```
output:
```
{"trade_id":235351199,"status":""}
```
### imx_offer_nft
```c
char* imx_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Used to create a buy offer on an NFT that is currently on sale. The offer amount should be at least 10% of the asking price or it will be rejected by the API.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char private_key[67] = "";
    char response[1000];
    std::cout << imx_offer_nft("0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", "244609703", ETH, 0.000001, NULL, 0, private_key, response, 1000) << std::endl;
}
```
output:
```
{"order_id":313775742,"status":"","time":0}
```
### imx_request_offer_nft
```c
char* imx_request_offer_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* seller_address_str, char* result_buffer, int buffer_size)
```
Request the signable message needed to submit a buy offer to IMX. After signing, the offer can be submitted using the imx_finish_sell_or_offer_nft function.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    std::cout << imx_request_offer_nft("0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", "244609703", ETH, 0.000001, NULL, 0, address, response, 1000) << std::endl;
}
```
output:
```
{"nonce":1150325110,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n24fd4b12f51029ec55ddb23c5a1432e8e8e587ddf481e7a2abf4cb72f0e2efbf"}
```
### imx_sell_nft
```c
char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Creates a sell order for an nft owned by the wallet corresponding to the provided private key. Server response is stored in the result_buffer. The sale price entered includes a 1% maker marketplace fee as well as any additional fees provided by the user. Protocol, taker and royalty fees are added later.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[] = ""; // Private key
    const char collection_address[] = "0xacb3c6a43d15b907e8433077b6d38ae40936fe2c"; // Gods unchained cards share this address
    const char token_id[] = "211653036"; // ID unique to the card to sell.
    char response[1000];
    Fee fee = { "0x3d248e3370bc947b8d225a680d0e4f57aba9640f", 10 }; // Add a 10% fee paid to 0x3d248e3370bc947b8d225a680d0e4f57aba9640f onto this sell offer.
    std::cout << imx_sell_nft(collection_address, token_id, ETH, 1, &fee, 1, key, response, 1000) << std::endl;
}
```
output:
```
{"order_id":243684486,"status":"","time":0}
```
### imx_request_sell_nft
```c
char* imx_request_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* seller_address_str, char* result_buffer, int buffer_size)
```
Request the signable message needed to submit a sell order to IMX. After signing, the offer can be submitted using the imx_finish_sell_or_offer_nft function.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    Fee fee = { "0x3d248e3370bc947b8d225a680d0e4f57aba9640f", 10 }; // Add a 10% fee paid to 0x3d248e3370bc947b8d225a680d0e4f57aba9640f to this sell offer.
    std::cout << imx_request_sell_nft("0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", "182524985", ETH, 1, &fee, 1, address, response, 1000) << std::endl;
}
```
output:
```
{"nonce":537331268,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n5c63017d32fbd0a411786be887f5403d70633ba8bff210412b16f14d7da8ac97"}
```

### imx_finish_sell_or_offer_nft
```c
char* imx_finish_sell_or_offer_nft(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
```
Submit a signed sell or offer order to IMX.
#### Example
```c
#include <iostream>
#include <string>
#include "IMXlib.h"
#include "nlohmann/json.hpp"

int main()
{
    using nlohmann::json;
    char private_key[67] = "";
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    imx_request_sell_nft("0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", "182524985", ETH, 1, NULL, 0, address, response, 1000);

    json response_data = json::parse(response); // Parse the response.
    std::string nonce = std::to_string(response_data["nonce"].get<__int64>());
    std::string message = response_data["signable_message"].get<std::string>();

    char imx_seed_sig[133];
    char imx_transaction_sig[133];
    eth_sign_message(imx_seed_message, private_key, imx_seed_sig, 133); // Calculate the stark key seed used for signing on IMX.
    eth_sign_message(message.c_str(), private_key, imx_transaction_sig, 133); // Calculate the transaction signature.

    std::cout << imx_finish_sell_or_offer_nft(nonce.c_str(), imx_seed_sig, imx_transaction_sig, response, 1000) << std::endl;
}
```
output:
```
{"order_id":313782727,"status":"","time":0}
```
### imx_transfer_nft
```c
char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Transfer an NFT from the wallet corresponding to the provided private key to a different address. Example output is from a successful transfer. Server response is stored in the result_buffer.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[] = ""; // Private key
    const char collection_address[] = "0xacb3c6a43d15b907e8433077b6d38ae40936fe2c"; // Gods unchained cards share this address
    const char token_id[] = "211653036";// ID unique to the card to transfer.
    const char address[] = "0x3d248e3370bc947b8d225a680d0e4f57aba9640f";
    char response[1000];
    std::cout << imx_transfer_nft(collection_address, token_id, address, key, response, 1000) << std::endl;
}
```
output:
```
{"transfer_ids":[152931695]}
```

### imx_transfer_nfts
```c
char* imx_transfer_nfts(NFT* nfts, int nft_count, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Allows for multiple NFTs to be transferred at once.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char private_key[67] = "";  // Private key
    NFT user_nfts[2] = { {"0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", 182524985 }, {"0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", 182567518} };
    char response[1000];
    std::cout << imx_transfer_nfts(user_nfts, 2, "0xa11738d1ed318fb27b2d37ab96adf0eab72b5ff4", private_key, response, 1000);
}
```
output:
```
{"transfer_ids":[235355739,235355740]}
```
### imx_request_transfer_nft
```c
char* imx_request_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size)
```
Prepares and returns a transfer that can be signed and submitted using imx_finish_transfer.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    std::cout << imx_request_transfer_nft("0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", "182524985", "0xa11738d1ed318fb27b2d37ab96adf0eab72b5ff4", address, response, 1000);
}
```
output:
```
{"nonce":1611903851,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n602fa606ec71d541db6bc642a09fc64c55b7893e4432be9b7a253e3f22eb90d5"}
```
### imx_request_transfer_nfts
```c
char* imx_request_transfer_nfts(NFT * nfts, int nft_count, const char* receiver_address, const char* sender_address, char* result_buffer, int buffer_size)
```
Prepares and returns a transfer of multiple NFTs that can be signed and submitted using imx_finish_transfer.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    NFT user_nfts[2] = { {"0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", 182524985 }, {"0xacb3c6a43d15b907e8433077b6d38ae40936fe2c", 182567518} };
    char response[1000];
    std::cout << imx_request_transfer_nfts(user_nfts, 2, "0xa11738d1ed318fb27b2d37ab96adf0eab72b5ff4", address, response, 1000);
}
```
output:
```
{"nonce":99740034,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n7a427a76d44a4874a7395a390e270ebed7bc9e17102719fc4054a78259bf7231"}
```
### imx_transfer_token
```c
char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Transfers token from the wallet corresponding to the provided private key to a  different address. Example output is from a successful transfer. Server response is stored in the result_buffer.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    const char key[] = ""; // Private key
    const char address[] = "0x3d248e3370bc947b8d225a680d0e4f57aba9640f";
    char response[1000];
    std::cout << imx_transfer_token(ETH, 0.000001, address, key, response, 1000) << std::endl; // Transfer 0.000001 ETH.
}
```
output:
```
{"transfer_ids":[152933155]}
```
### imx_request_transfer_token
```c
char* imx_request_transfer_token(const char* token_id_str, double amount, const char* receiver_address_str, const char* sender_address_str, char* result_buffer, int buffer_size)
```
Prepares and returns a signable transfer of multiple NFTs that can be signed and submitted using imx_finish_transfer.
#### Example
```c
#include <iostream>
#include "IMXlib.h"

int main()
{
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    std::cout << imx_request_transfer_token(ETH, 0.000001, "0xa11738d1ed318fb27b2d37ab96adf0eab72b5ff4", address, response, 1000) << std::endl;
}
```
output:
```
{"nonce":1421405824,"signable_message":"Only sign this request if you’ve initiated an action with Immutable X.\n\nFor internal use:\n7c1682ea7182e6d859f8792f700c80a6116fe2eeb09a5aac3829769fdcc784ce"}
```
### imx_finish_transfer
```c
char* imx_finish_transfer(const char* nonce_str, const char* imx_seed_sig_str, const char* imx_transaction_sig_str, char* result_buffer, int buffer_size)
```
Submits a previously requested and signed transfer to IMX.
#### Example
```c
#include <iostream>
#include <string>
#include "IMXlib.h"
#include "nlohmann/json.hpp"

int main()
{
    using nlohmann::json;
    char private_key[67] = ""; // Private key
    char address[43] = "0x216df17ec98bae6047f2c5466162333f1aee23dc";
    char response[1000];
    imx_request_transfer_token(ETH, 0.000001, "0xa11738d1ed318fb27b2d37ab96adf0eab72b5ff4", address, response, 1000);

    json response_data = json::parse(response); // Parse the response.
    std::string nonce = std::to_string(response_data["nonce"].get<__int64>());
    std::string message = response_data["signable_message"].get<std::string>();

    char imx_seed_sig[133];
    char imx_transaction_sig[133];
    eth_sign_message(imx_seed_message, private_key, imx_seed_sig, 133); // Calculate the stark key seed used for signing on IMX.
    eth_sign_message(message.c_str(), private_key, imx_transaction_sig, 133); // Calculate the transaction signature.

    std::cout << imx_finish_transfer(nonce.c_str(), imx_seed_sig, imx_transaction_sig, response, 1000) << std::endl;
}
```
output:
```
{"transfer_ids":[235358011]}
```
## Disclaimer
This is **not** an official library for writing application that interact with IMX. Because of this, it is possible that future changes to the IMX api could break its functionality. Use it at your own risk. IMX itself also offers some resources to programmers looking to write code on the IMX platform. However, unlike this library, the official guides focus almost exclusively on making web applications.
