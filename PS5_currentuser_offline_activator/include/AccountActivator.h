#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>



#define USERNAME_ENTITY_NUMBER      0x7800200
#define USERNAME_ENTITY_NUMBER_2    0x7940200

#define ACCOUNT_ID_ENTITY_NUMBER    0x7800500
#define ACCOUNT_ID_ENTITY_NUMBER_2  0x7940500

#define ACCOUNT_TYPE_ENTITY_NUMBER   0x780b007
#define ACCOUNT_TYPE_ENTITY_NUMBER_2 0x794b007

#define ACCOUNT_ENTITY_FLAGS_NUMBER    0x7800800
#define ACCOUNT_ENTITY_FLAGS_NUMBER_2  0x7940800

#define ACCOUNT_TYPE_MAX 17

extern "C" int sceUserServiceInitialize(uint32_t*);
extern "C" int sceUserServiceGetForegroundUser(int*);
extern "C" int sceUserServiceGetUserName(int, char*, size_t);

extern "C" int sceRegMgrGetInt(int, int*);
extern "C" int sceRegMgrGetStr(int, char*, size_t);
extern "C" int sceRegMgrGetBin(int, void*, size_t);

extern "C" int sceRegMgrSetInt(int, int);
extern "C" int sceRegMgrSetBin(int, const void*, size_t);
extern "C" int sceRegMgrSetStr(int, const char*, size_t);

typedef std::vector<std::string> AccountList;


struct User
{
    std::string Username;
    uint32_t account_number;
    uint64_t accountID;
    char AccountType[ACCOUNT_TYPE_MAX];
};


class Activator
{
public:
    Activator();
    bool Activate();
    void GetPSAccount(std::string& account);

    inline bool Valid() const { return currentUser.account_number != -1; }
    bool IsNotActivated();

    User currentUser;
private:
    int GetEntityNumber(int a, int d, int e);
    uint32_t GetRegistryFromUsername(const std::string& username);
    uint64_t GetAccountID(uint32_t account_number);
    uint32_t GetAccountType(uint32_t account_number, char* account_type);

    void SetAccountID(uint32_t account_number, uint64_t AccountID);
    void SetAccountType(uint32_t account_number, char* AccountType);
    void SetAccountFlags(uint32_t account_number, uint32_t Flags);




};