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
