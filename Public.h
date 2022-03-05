/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_DevOSASPhilippovich191351,
    0x38b4c2cf,0xf400,0x4ed4,0xb5,0xb9,0xff,0xd6,0x37,0x38,0x47,0x66);
// {38b4c2cf-f400-4ed4-b5b9-ffd637384766}
