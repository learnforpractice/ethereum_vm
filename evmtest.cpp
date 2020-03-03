#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/fixed_bytes.hpp>
#include "eth_account.hpp"
#include "table_struct.hpp"

using namespace std;
using namespace eosio;


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
    void evm_execute_test(const uint8_t* tests, uint32_t _size);

    void load_secp256k1_ecmult_static_context() {
        eosio::check(false, "not implemented!");
    }

    void* get_secp256k1_ecmult_static_context() {
        eosio::check(false, "not implemented!");
        return nullptr;
    }

    void apply(uint64_t receiver, uint64_t code, uint64_t action) {
        if (action == "clearenv"_n.value) {
            eth_account_clear_all();
        } else if (action == "setaddrinfo"_n.value) {
            auto info = unpack_action_data<address_info>();
            eth_account_create(info.address, code);
            eth_account_set_nonce(info.address, info.nonce);
            // printhex(info.balance.data(), info.balance.size());print("\n");
            eosio::check(info.balance.size()==32, "bad balance value!!");
            eth_account_set_balance(info.address, *(eth_uint256*)info.balance.data());
            eth_account_set_code(info.address, info.code);
            for (uint32_t i=0;i<info.storage.size();i+=2) {
                auto& key = info.storage[i*2];
                auto& value = info.storage[i*2+1];
                // printhex(key.data(), key.size());print(":");printhex(value.data(), value.size());
                eth_account_set_value(info.address, key, value);
            }
        } else if (action == "raw"_n.value) {
            auto a = unpack_action_data<raw>();
            evm_execute_test((uint8_t*)a.trx.data(), a.trx.size());
        } else if (action == "clearenv"_n.value) {
            eth_account_clear_all();
        }
    }
}
