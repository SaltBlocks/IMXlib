# IMXlib

Unofficial library for interacting with IMX.\
This README is a work in progress. I'll try to write some example code using the library in the coming weeks.

## Usage
Binaries for use on 32 and 64-bit windows can be found in the releases section.
Exported functions and constants can be found in IMXlib.h and are implemented in IMXlib.cpp.
Sections below cover the exported functions and how to use them.\
\
The easiest way to use this project is to download the example visual studio project from the [releases section](https://github.com/SaltBlocks/IMXlib/releases). This can also be downloaded directly [here](https://github.com/SaltBlocks/IMXlib/releases/download/v1.0/IMXlib.visual.studio.project.zip).
If you have visual studio installed and properly setup to compile c++ programs, this project should compile straight away without having to change any settings. The example program is dynamically linked to IMXlib and curl. It can use all the functions covered below. By default it will generate a new ethereum private key and print that together with the address and the signature for the string "Hello World!" every time it is run. 

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
### imx_get_token_trade_fee
```c
int imx_get_token_trade_fee(const char* token_address_str, const char* token_id, CURL * curl = NULL)
```
Gets the fee percentage that is added when selling this card on the IMX platform. The fee includes the protocol, royalty and marketplace maker fees. Marketplace taker fees are not included as these aren't known but this will in most cases add 1% more to the buy price.
The token_address is the same for all assets in the collection it is part of. Both the collection address and token id can be found either using the imx api and are also listed on [immutascan](https://immutascan.io/). You can find the card from the example on immutascan [here](https://immutascan.io/address/0xacb3c6a43d15b907e8433077b6d38ae40936fe2c/211653036). The function returns the fee percentage as an integer.
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
char* imx_buy_nft(unsigned long long order_id, const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee * fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Buys the provided order using the wallet corresponding to the provided private key. The order_id, nft_address and id can all be retrieved from orders found using the [imx api](https://docs.x.immutable.com/reference#/operations/listOrders). The token_id is the token_address of the asset you are spending (can be found in the order) or simply "ETH" if you are buying using ethereum. The price variable should be equal to the price you will be paying including all fees. If it differs from the actual price, the server will return an error message. 
### imx_sell_nft
```c
char* imx_sell_nft(const char* nft_address_str, const char* nft_id_str, const char* token_id_str, double price, Fee* fees, int fee_count, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Creates a sell order for an nft owned by the wallet corresponding to the provided private key. Server response is stored in the result_buffer.
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
### imx_transfer_nft
```c
char* imx_transfer_nft(const char* nft_address_str, const char* nft_id_str, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
```
Transfer an nft from the wallet corresponding to the provided private key to a different address. Example output is from a successful transfer. Server response is stored in the result_buffer.
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
### imx_transfer_token
```c
char* imx_transfer_token(const char* token_id_str, double amount, const char* receiver_address, const char* eth_priv_str, char* result_buffer, int buffer_size)
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

## Disclaimer
This is **not** an official library for writing application that interact with IMX. Because of this, it is possible that future changes to the IMX api could break its functionality. Use it at your own risk. IMX itself also offers some resources to programmers looking to write code on the IMX platform. However, unlike this library, the official guides focus almost exclusively on making web applications.