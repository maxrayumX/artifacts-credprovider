@echo OFF
SETLOCAL EnableDelayedExpansion

REM A Windows domain user should be able to run this against a feed in an AAD-back AzDO org 
REM and all scenarios should succeed non-interactively.

set TEST_FEED=%1

echo "Testing MSAL with broker"
set NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=true
set NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER=true
CALL :TEST_FRAMEWORKS
IF %ERRORLEVEL% NEQ 0 (
    echo "Failed: %ERRORLEVEL%"
    exit /b %ERRORLEVEL%
)

echo "Testing MSAL without broker"
set NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=true
set NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER=false
CALL :TEST_FRAMEWORKS
IF %ERRORLEVEL% NEQ 0 (
    echo "Failed: %ERRORLEVEL%"
    exit /b %ERRORLEVEL%
)

echo "Testing ADAL"
set NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=false
set NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER=
CALL :TEST_FRAMEWORKS
IF %ERRORLEVEL% NEQ 0 (
    echo "Failed: %ERRORLEVEL%"
    exit /b %ERRORLEVEL%
)

echo "All tests passed!"
exit /b 0


:TEST_FRAMEWORKS
for %%I in ("net6.0","netcoreapp3.1","net461") DO (
    del /q "!UserProfile!\AppData\Local\MicrosoftCredentialProvider\*.dat" 2>NUL
    echo Testing %%I with NUGET_CREDENTIALPROVIDER_MSAL_ENABLED=!NUGET_CREDENTIALPROVIDER_MSAL_ENABLED! NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER=!NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER!
    dotnet run -f %%I --project CredentialProvider.Microsoft\CredentialProvider.Microsoft.csproj -- -N -U !TEST_FEED! -V Debug -R > test.%%I.%NUGET_CREDENTIALPROVIDER_MSAL_ENABLED%.%NUGET_CREDENTIALPROVIDER_MSAL_ALLOW_BROKER%.log
    IF !ERRORLEVEL! NEQ 0 (
        echo "Previous command execution failed: !ERRORLEVEL!"
        exit /b !ERRORLEVEL!
    )
)