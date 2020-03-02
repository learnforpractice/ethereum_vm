#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/fixed_bytes.hpp>
#include "eth_account.hpp"

using namespace std;
using namespace eosio;

struct [[eosio::table]] evm_storage {
    vector<uint8_t> key;
    vector<uint8_t> value;    
    EOSLIB_SERIALIZE( evm_storage, (key)(value) )
};

struct [[eosio::table]] address_info {
    vector<uint8_t>         address;
    uint64_t                nonce;
    vector<uint8_t>         balance;
    vector<uint8_t>         code;

    EOSLIB_SERIALIZE( address_info, (address)(nonce)(balance)(code) )
};

struct [[eosio::table]] testenv {
    vector<uint8_t>     current_coinbase;
    uint64_t            current_difficulty;
    uint64_t            current_gas_limit;
    uint64_t            current_number;
    uint64_t            current_timestamp;

    EOSLIB_SERIALIZE( testenv, (current_coinbase)(current_difficulty)(current_gas_limit)(current_number)(current_timestamp) )
};

struct raw {
    vector<char> trx;
    vector<char> sender;
    EOSLIB_SERIALIZE( raw, (trx)(sender) )
};

/*
"currentCoinbase" : "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
"currentDifficulty" : "0x0100",
"currentGasLimit" : "0x0f4240",
"currentNumber" : "0x00",
"currentTimestamp" : "0x01"


{'0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6': {
    'balance': '0x152d02c7e14af6800000',
    'code': '0x6000600020600055',
    'nonce': '0x00',
    'storage': {}
    }
}
*/


void reset_env() {

}

extern "C" {
    __attribute__((eosio_wasm_import))
    int evm_execute(const char *raw_trx, uint32_t raw_trx_size, const char *sender_address, uint32_t sender_address_size);

    void load_secp256k1_ecmult_static_context() {
        eosio::check(false, "not implemented!");
    }

    void* get_secp256k1_ecmult_static_context() {
        eosio::check(false, "not implemented!");
        return nullptr;
    }

    void apply(uint64_t receiver, uint64_t first_receiver, uint64_t action) {
        if (action == "setaddrinfo"_n.value) {
            auto info = unpack_action_data<address_info>();
            eosio::check(info.address.size() == 20, "bad address size!!");
            eth_address &addr = *(eth_address*)info.address.data();
            eth_account_create(addr, first_receiver);
            eth_account_set_nonce(addr, info.nonce);
            eth_account_set_balance(addr, *(eth_uint256*)&info.balance);
            eth_account_set_code(addr, info.code);

        // vector<uint8_t>         address;
        // uint64_t                nonce;
        // uint64_t                balance;
        // vector<uint8_t>         code;
        }  else if (action == "raw"_n.value) {
            auto a = unpack_action_data<raw>();
            evm_execute(a.trx.data(), a.trx.size(), a.sender.data(), a.sender.size());
        } else if (action == "clearenv"_n.value) {
            eth_account_clear_all();
        }
    }
}
