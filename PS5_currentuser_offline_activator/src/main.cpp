#include <cstdio>
#include <iostream>
#include "../include/AccountActivator.h"

//
// Use this on Chiaki as AccountID => 776t3u++rd4=
//

int main(int argc, char const *argv[])
{
    Activator activator;

    if (activator.Valid() && activator.IsNotActivated())
    {
        std::printf("Activating account %s...\n", activator.currentUser.Username.c_str());

        if (activator.Activate())
        {
            std::puts("Activated!");
        }
    }
    else
    {
        std::puts("Invalid account or already activated!");
    }

    return 0;
}
