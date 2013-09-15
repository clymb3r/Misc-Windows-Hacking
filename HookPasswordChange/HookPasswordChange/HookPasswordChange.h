#include "stdafx.h"

using namespace std;

#define DllExport extern "C" __declspec( dllexport )

DllExport void InitHooking();
DllExport void VoidFunc(); //For use with Invoke-ReflectivePEInjection. Simply calls InitHooking().