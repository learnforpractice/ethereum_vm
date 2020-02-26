#include "eth_account.hpp"

#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>

#include <eosio/singleton.hpp>

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>

#include <eosio/system.hpp>
#include <vector>

using namespace std;
using namespace eosio;

#define SIZE_256BIT 32
#define SIZE_ADDRESS 20

struct [[eosio::table]] ethaccount {
    uint64_t                        index;
    uint64_t                        creator;
    int64_t                         nonce;
    std::vector<char>               address;
    asset                           balance;
    ethaccount() {
        address.resize(SIZE_ADDRESS);
    }
    uint64_t primary_key() const { return index; }

    checksum256 by_address() const {
       auto ret = checksum256();//address;
       memset(ret.data(), 0, sizeof(checksum256));
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }

    uint64_t by_creator() const {
        return creator;
    }

    EOSLIB_SERIALIZE( ethaccount, (index)(creator)(nonce)(address)(balance) )
};

struct [[eosio::table]] account_state {
    uint64_t                        index;
    vector<char>                    key;
    vector<char>                    value;

    account_state() {
        key.resize(32);
        value.resize(32);
    }

    uint64_t primary_key() const { return index; }

    checksum256 by_key() const {
        auto ret = checksum256();
        check(key.size() == 32, "bad key size!");
        memcpy(ret.data(), key.data(), 32);
        return ret;
    }

    EOSLIB_SERIALIZE( account_state, (index)(key)(value) )
};

struct [[eosio::table]] ethcode {
    uint64_t                        index;
    std::vector<char>               address;
    vector<char>                    code;
    uint64_t                        version;
    uint64_t primary_key() const { return index; }

    ethcode() {
        address.resize(SIZE_ADDRESS);
    }

    checksum256 by_address() const {
       auto ret = checksum256();
       memset(ret.data(), 0, sizeof(checksum256));
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }

    EOSLIB_SERIALIZE( ethcode, (index)(address)(code)(version) )
};

struct [[eosio::table]] accountcounter {
    uint64_t                        count;
    int32_t                         chain_id;
    EOSLIB_SERIALIZE( accountcounter, (count)(chain_id) )
};

/*
This struct used to map 256 bit key to 64 bit primary key, 
there's no need to worry about the counter overflow, 
the reason is:
let's suppose we can do one store/delete operation in 1us,
that means we can do 1,000,000 operations in 1s,
and it need about 584942.4(0xffffffffffffffff/1000000/60/60/24/365) years to overflow the counter
that's safe enough
*/
struct [[eosio::table]] key256counter {
    uint64_t                        count;
    EOSLIB_SERIALIZE( key256counter, (count) )
};

struct [[eosio::table]] addressmap {
    uint64_t                        creator;
    std::vector<char>               address;
    uint64_t primary_key() const { return creator; }
    addressmap() {
        address.resize(20);
    }
    checksum256 by_address() const {
       auto ret = checksum256();
       memset(ret.data(), 0, sizeof(checksum256));
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }
    EOSLIB_SERIALIZE( addressmap, (creator)(address) )
};

typedef multi_index<"addressmap"_n,
                    addressmap,
                    indexed_by< "byaddress"_n, const_mem_fun<addressmap, checksum256, &addressmap::by_address> >
                > addressmap_table;

typedef eosio::singleton< "global"_n, accountcounter >   account_counter;
typedef eosio::singleton< "global2"_n, key256counter >   key256_counter;


typedef multi_index<"ethaccount"_n,
                ethaccount,
                indexed_by< "byaddress"_n, const_mem_fun<ethaccount, checksum256, &ethaccount::by_address> >,
                indexed_by< "bycreator"_n, const_mem_fun<ethaccount, uint64_t, &ethaccount::by_creator> > 
                > ethaccount_table;

typedef multi_index<"accountstate"_n,
                account_state,
                indexed_by< "bykey"_n,
                const_mem_fun<account_state, checksum256, &account_state::by_key> > > account_state_table;


typedef multi_index<"ethcode"_n, ethcode> ethcode_table;

uint64_t get_next_key256_index(uint64_t payer) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    key256_counter counter(name(code), scope);

    key256counter a = {0};
    a = counter.get_or_default(a);
    a.count += 1;
    counter.set(a, name(payer));
    return a.count;
}

uint64_t get_next_eth_address_index(uint64_t payer) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    account_counter counter(name(code), scope);
    accountcounter a = {0};
    a = counter.get_or_default(a);
    a.count += 1;
    counter.set(a, name(payer));
    return a.count;
}

void eth_set_chain_id(int32_t chain_id) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    uint64_t payer = current_receiver().value;

    account_counter counter(name(code), scope);

    accountcounter a = {0};
    a = counter.get_or_default(a);
    a.chain_id = chain_id;
    counter.set(a, name(payer));
}

int32_t eth_get_chain_id() {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    account_counter counter(name(code), scope);

    accountcounter a = {0, 0};
    a = counter.get_or_default(a);
    return a.chain_id;
}

bool eth_account_bind_address_to_creator(eth_address& address, uint64_t creator) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    name payer(creator);

    addressmap_table table(name(code), scope);
    check (table.end() == table.find(creator), "eth address already bind to an EOS account");

    table.emplace( payer, [&]( auto& row ) {
        row.creator = creator;
        row.address.resize(SIZE_ADDRESS);
        memcpy(row.address.data(), address.data(), SIZE_ADDRESS);
    });
    return true;
}

bool eth_account_find_address_by_binded_creator(uint64_t creator, eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    name payer(creator);

    addressmap_table table(name(code), scope);
    auto itr = table.find(creator);
    check (table.end() != itr, "creator does not bind to an eth address");
    memcpy(address.data(), itr->address.data(), SIZE_ADDRESS);
    return true;
}

uint64_t eth_account_find_creator_by_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return 0;
    }
    return itr->creator;
}

uint64_t eth_account_find_index_by_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return 0;
    }
    return itr->index;
}

bool eth_account_find_creator_and_index_by_address(eth_address& address, uint64_t& creator, uint64_t& index) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return false;
    }
    creator = itr->creator;
    index = itr->index;
    return true;
}

bool eth_account_create(eth_address& address, uint64_t creator) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    uint64_t payer = creator;

    require_auth(name(creator));

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    // eosio::print("\n", creator, "\n");
    // eosio::printhex(address.data(), address.size());
    
    auto itr2 = idx_sec.find(_address);
    if (itr2 == idx_sec.end()) {
        uint64_t index = get_next_eth_address_index(creator);
        // eosio::print("address not found!\n");
        mytable.emplace( name(payer), [&]( auto& row ) {
            asset a(0, symbol(ETH_ASSET_SYMBOL, 4));
            row.balance = a;
            row.address.resize(SIZE_ADDRESS);
            memcpy(row.address.data(), address.data(), SIZE_ADDRESS);
            row.index = index;
            row.creator = creator;
            row.nonce = 1;
        });
        return true;
    } else {
        eosio::check(false, "eth address already exists!");
    }
    return false;
}

bool eth_account_exists(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    
    auto idx = idx_sec.find(_address);
    if (idx == idx_sec.end()) {
        return false;
    }
    return true;
}

void eth_account_check_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

//    eosio::printhex(address.data(), address.size());

    auto idx = idx_sec.find(_address);
    check(idx != idx_sec.end(), "eth address does not exists!");
}

uint64_t eth_account_get_info(eth_address& address, uint64_t* creator, int64_t* nonce, int64_t* amount) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto idx = idx_sec.find(_address);
    if (idx == idx_sec.end()) {
        return 0;
    }
    if (nonce) {
        *nonce = idx->nonce;
    }
    if (amount) {
        *amount = idx->balance.amount;
    }
    if (creator) {
        *creator = idx->creator;
    }
    return idx->index;;
}

bool eth_account_get(eth_address& address, ethaccount& account) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return false;
    }
    account = *itr;
    return true;
}

bool eth_account_set(eth_address& address, const ethaccount& account) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    uint64_t payer = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    account_counter counter(name(code), scope);
    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        eosio::check(false, "eth_account_set: account does not exists!");
        return false;
    }
    auto itr2 = mytable.find(itr->index);
    mytable.modify( itr2, name(payer), [&]( auto& row ) {
        row = account;
    });
    return true;
}

int64_t eth_account_get_balance(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    check(itr != idx_sec.end(), "get_balance:address does not created!");

    return itr->balance.amount;
}

bool eth_account_set_balance(eth_address& address, int64_t amount) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    uint64_t payer = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    check(itr != idx_sec.end(), "set_balance:address does not created");
    auto itr2 = mytable.find(itr->index);
    mytable.modify( itr2, name(payer), [&]( auto& row ) {
        row.balance.amount = amount;
    });
    return true;
}

bool eth_account_get_code(eth_address& address, std::vector<unsigned char>& evm_code) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }

//    check(creator, "get_code: address creator not found!");
    
    uint64_t code = current_receiver().value;

    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        return false;
    }

    evm_code.resize(itr->code.size());
    memcpy(evm_code.data(), itr->code.data(), evm_code.size());
    return true;
}

bool eth_account_set_code(eth_address& address, const std::vector<unsigned char>& evm_code) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_code: address not created!");

    require_auth(name(creator));
    
    uint64_t code = current_receiver().value;


    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        mytable.emplace( name(creator), [&]( auto& row ) {
            row.index = address_index;
            row.address.resize(SIZE_ADDRESS);
            memcpy(row.address.data(), address.data(), SIZE_ADDRESS);
            row.code.resize(evm_code.size());
            memcpy(row.code.data(), evm_code.data(), evm_code.size());
        });
    } else {
        check(false, "can not modify evm code!");
        mytable.modify( itr, name(creator), [&]( auto& row ) {
            row.code.resize(evm_code.size());
            memcpy(row.code.data(), evm_code.data(), evm_code.size());
        });
    }

    return true;
}

uint32_t  eth_account_get_code_size(eth_address& address) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }

//    check(creator, "get_code: address creator not found!");
    
    uint64_t code = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        return 0;
    }
    return itr->code.size();
}

bool eth_account_clear_code(eth_address& address) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_code: address not created!");

    require_auth(name(creator));
    
    uint64_t code = current_receiver().value;


    ethcode_table mytable(name(code), creator);

    auto itr = mytable.find(address_index);

    if (itr == mytable.end()) {
        return false;
    }
    mytable.erase(itr);

    return true;
}

bool eth_account_get_nonce(eth_address& address, uint64_t& nonce) {
    ethaccount account;
    if (!eth_account_get(address, account)) {
        return false;
    }
    nonce = account.nonce;
    return true;
}

bool eth_account_set_nonce(eth_address& address, uint64_t nonce) {
    ethaccount account;
    if (!eth_account_get(address, account)) {
        return 0;
    }
    account.nonce = nonce;
    return eth_account_set(address, account);
}

bool eth_account_get_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }
//    check(ret, "get_value:address not created!");
    
    uint64_t code = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    account_state_table mytable(name(code), address_index);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        return false;
    }

    memcpy(value.data(), itr->value.data(), SIZE_256BIT);
//    always return true
    return true;
}

bool eth_account_set_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");
//    eosio::check(creator, "set_value: address creator not found!");

    require_auth(name(creator));
    
    uint64_t code = current_receiver().value;

    account_state_table mytable(name(code), address_index);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        mytable.emplace( name(creator), [&]( auto& row ) {
            uint64_t key256_index = get_next_key256_index(creator);
            row.index = key256_index;
            row.key.resize(32);
            row.value.resize(32);
            memcpy(row.key.data(), key.data(), SIZE_256BIT);
            memcpy(row.value.data(), value.data(), SIZE_256BIT);
        });
    } else {
        auto itr2 = mytable.find(itr->index);
        mytable.modify( itr2, name(creator), [&]( auto& row ) {
            check(row.value.size() == 32, "bad value size!");
            memcpy(row.value.data(), value.data(), SIZE_256BIT);
        });
    }

    return true;
}

bool eth_account_clear_value(eth_address& address, key256& key) {
    uint64_t creator;
    creator = eth_account_find_creator_by_address(address);
    eosio::check(creator, "creator not found");

    uint64_t code = current_receiver().value;

    account_state_table mytable(name(code), creator);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        return false;
    }
    auto itr2 = mytable.find(itr->index);
    mytable.erase(itr2);
    return true;
}
