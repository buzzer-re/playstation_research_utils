#include "../include/AccountActivator.h"


Activator::Activator()
{
    //
    // Get current logged user
    //
    int ret = sceUserServiceInitialize(NULL);

    if (ret)
    {
        std::puts("Error sceUserServiceInitialize");
        return;
    }

    int user_id;
    char username[100] = {0};
    sceUserServiceGetForegroundUser(&user_id);
    sceUserServiceGetUserName(user_id, username, sizeof(username));  
    currentUser.Username = std::string(username);
    // currentUser.Username = "User1";
    currentUser.account_number = GetRegistryFromUsername(currentUser.Username);

    if (currentUser.account_number == -1)
    {
        std::printf("Invalid user %s, aborting...\n", currentUser.Username.c_str());
        return;    
    }

    currentUser.accountID = GetAccountID(currentUser.account_number);
    GetAccountType(currentUser.account_number, currentUser.AccountType);

    std::printf("Current user => %s\n", currentUser.Username.c_str());
    std::printf("Account register number => %d\n", currentUser.account_number);
    std::printf("User Account ID => %lx\n", currentUser.accountID);
    std::printf("AccountType => %s\n", currentUser.AccountType);
}


uint32_t Activator::GetRegistryFromUsername(const std::string& username)
{
    char reg_username[100] = {0};

    for (ssize_t i = 0; i < 100; ++i)
    {
        int reg_number = GetEntityNumber(i, USERNAME_ENTITY_NUMBER, USERNAME_ENTITY_NUMBER_2);
        sceRegMgrGetStr(reg_number, reg_username, 100);
        
        if (!strncmp(username.c_str(), reg_username, username.size()))
        {
            return i;
        }
    }

    return -1;
}


uint64_t Activator::GetAccountID(uint32_t account_number)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ID_ENTITY_NUMBER, ACCOUNT_ID_ENTITY_NUMBER_2);
    uint32_t val = 0;

    sceRegMgrGetBin(n, &val, sizeof(uint64_t));

    return val;
}


void Activator::SetAccountID(uint32_t account_number, uint64_t AccountID)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ID_ENTITY_NUMBER, ACCOUNT_ID_ENTITY_NUMBER_2);

    sceRegMgrSetBin(n, &AccountID, sizeof(uint64_t));
}


void Activator::SetAccountType(uint32_t account_number, char* AccountType)
{
    int n = GetEntityNumber(account_number, ACCOUNT_TYPE_ENTITY_NUMBER, ACCOUNT_TYPE_ENTITY_NUMBER_2);
    
    sceRegMgrSetStr(n, AccountType, ACCOUNT_TYPE_MAX);
}


uint32_t Activator::GetAccountType(uint32_t account_number, char* account_type)
{
    int n = GetEntityNumber(account_number, ACCOUNT_TYPE_ENTITY_NUMBER, ACCOUNT_TYPE_ENTITY_NUMBER_2);

    return sceRegMgrGetStr(n, account_type, ACCOUNT_TYPE_MAX);
}


void Activator::SetAccountFlags(uint32_t account_number, uint32_t Flags)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ENTITY_FLAGS_NUMBER, ACCOUNT_ENTITY_FLAGS_NUMBER_2);
    sceRegMgrSetInt(n, Flags);
}


bool Activator::IsNotActivated()
{
    return currentUser.accountID == 0;
}

bool Activator::Activate()
{    
    if (IsNotActivated())
    {
        uint64_t accountID = 0xDEADBEEFDEADBEEF;
        char account_type[ACCOUNT_TYPE_MAX] = "np";
        uint32_t flags = 4098;

        SetAccountID(currentUser.account_number, accountID);
        SetAccountType(currentUser.account_number, account_type);
        SetAccountFlags(currentUser.account_number, flags);

        return true;
    }

    return false;
}


int Activator::GetEntityNumber(int a, int d, int e)
{
    int b = 16U;
    int c = 65536U;

    if (a < 1 || a > b) 
    {
        return e;
    }

    return (a - 1) * c + d;
}

void Activator::GetPSAccount(std::string& account)
{   
    
}

