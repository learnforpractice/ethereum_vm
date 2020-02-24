#pragma once
#include <stdlib.h>
#include <vector>
#include <array>
/*
#define ALIGNED(X) __attribute__ ((aligned (16))) X
struct ALIGNED(eth_address) {
    unsigned char data[20];
};
*/
#define ETH_ASSET_SYMBOL "SYS"
static constexpr int64_t max_amount = (1LL << 62) - 1;

// typedef std::array<unsigned char, 20> eth_address;

typedef struct eth_address
{
    uint8_t bytes[20];
    uint8_t* data() {return bytes;};
    uint32_t size() {return 20;}
} eth_address;

typedef std::array<unsigned char, 32> key256;
typedef std::array<unsigned char, 32> value256;

#define ETH_ADDRESS(addr) *(eth_address*)&addr

// typedef struct bytes32
// {
//     uint8_t bytes[32];
// } bytes32;

// typedef struct eth_address
// {
//     uint8_t bytes[20];
// } eth_address;

// typedef std::vector<unsigned char> key256;
// typedef std::vector<unsigned char> value256;

#define SIZE_256BIT 32
#define SIZE_ADDRESS 20

int32_t eth_get_chain_id();
void    eth_set_chain_id(int32_t chain_id);

bool    eth_account_bind_address_to_creator(eth_address& address, uint64_t creator);
bool    eth_account_find_address_by_binded_creator(uint64_t creator, eth_address& address);


bool    eth_account_create(eth_address& address, uint64_t creator);
bool    eth_account_exists(eth_address& address);
void    eth_account_check_address(eth_address& address);
uint64_t eth_account_find_creator_by_address(eth_address& address);

uint64_t eth_account_get_info(eth_address& address, uint64_t* creator, int32_t* nonce, int64_t* amount);

int64_t  eth_account_get_balance(eth_address& address);
bool    eth_account_set_balance(eth_address& address, int64_t amount);

bool    eth_account_get_code(eth_address& address, std::vector<unsigned char>& evm_code);
bool    eth_account_set_code(eth_address& address, const std::vector<unsigned char>& evm_code);
uint32_t  eth_account_get_code_size(eth_address& address);
bool    eth_account_clear_code(eth_address& address);
bool    eth_account_get_nonce(eth_address& address, uint32_t& nonce);
bool    eth_account_set_nonce(eth_address& address, uint32_t nonce);

bool    eth_account_get_value(eth_address& address, key256& key, value256& value);
bool    eth_account_set_value(eth_address& address, key256& key, value256& value);
bool    eth_account_clear_value(eth_address& address, key256& key);

#define EVM_API __attribute__ ((visibility ("default")))
