@echo OFF
SETLOCAL EnableDelayedExpansion

REM A Windows domain user should be able to run this against a feed in an AAD-back AzDO org 
REM and all scenarios should succeed non-interactively.

set TEST_FEED=%1

echo "Testing ADAL"
set NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=false
CALL :TEST_FRAMEWORKS
IF %ERRORLEVEL% NEQ 0 (
    echo "ADAL failed: %ERRORLEVEL%"
    exit /b %ERRORLEVEL%
)

echo "Testing MSAL"
set NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=true
CALL :TEST_FRAMEWORKS
IF %ERRORLEVEL% NEQ 0 (
    echo "MSAL failed: %ERRORLEVEL%"
    exit /b %ERRORLEVEL%
)

echo "All tests passed!"
exit /b 0


:TEST_FRAMEWORKS
for %%I in ("netcoreapp3.1","net461","net6-windows10.0.17763.0") DO (
    del "!UserProfile!\AppData\Local\MicrosoftCredentialProvider\ADALTokenCache.dat" 2>NUL
    del "!UserProfile!\AppData\Local\MicrosoftCredentialProvider\SessionTokenCache.dat" 2>NUL
    echo Testing %%I with NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=!NUGET_CREDENTIALPROVIDER_MSAL_ENABLED!
    dotnet run -f %%I --project CredentialProvider.Microsoft\CredentialProvider.Microsoft.csproj -- -N -U !TEST_FEED! -V Debug -R > test.%%I.%NUGET_CREDENTIALPROVIDER_MSAL_ENABLED%.log
    IF !ERRORLEVEL! NEQ 0 (
        echo "Previous command execution failed: !ERRORLEVEL!"
        exit /b !ERRORLEVEL!
    )
)