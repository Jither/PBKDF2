Jither.PBKDF2
===========

Important note, August 2016
---------------------------
There is now an MS-supported implementation of PBKDF2 (for .NET Standard 1.3 and .NET Framework 4.5.1 targets) in the `Microsoft.AspNetCore.Cryptography.KeyDerivation` Nuget package (note that contrary to the package name, it is *not* for ASP.NET Core exclusively). When possible, that package should be preferred to this one.  
More information here: https://docs.asp.net/en/latest/security/data-protection/consumer-apis/password-hashing.html

Flexible PBKDF2 implementation for the .NET Framework.

The PBKDF2 implementation included with .NET 2.0 and newer - `Rfc2898DeriveBytes` - is hardcoded to use HMAC-SHA1 as the underlying pseudo random function (PRF).

Jither.PBKDF2 consists of:

- `PBKDF2DeriveBytes` - which allows a custom PRF through a simple `IPseudoRandomFunction` interface.
- A few example implementations of `IPseudoRandomFunction` using other .NET HMAC implementations (HMAC-SHA256, HMAC-SHA512 etc.)
- A small suite of tests, mainly checking output against published test vectors.
- A quickly hacked together test tool (AwpTest) for [anti-weakpasswords](https://github.com/Anti-weakpasswords)

Since `PBKDF2DeriveBytes` subclasses `DeriveBytes` (like `Rfc2898DeriveBytes`) usage is similar:

    using (var prf = new HMACSHA512PseudoRandomFunction(input))
    {
        using (var hash = new PBKDF2DeriveBytes(prf, salt, 1000))
        {
            var result = hash.GetBytes(32);
        }
    }

__Important note on targets__
The master/default branch targets .NET Framework 4.5.1 (because that's what I currently use.
There's also a "net3.5" branch targetting .NET Framework 3.5 Client Profile.
	
__Note:__

Although the code in this repository is extracted from production code, it is mainly intended for educational purposes and something to build upon - not as a full-fledged library.
