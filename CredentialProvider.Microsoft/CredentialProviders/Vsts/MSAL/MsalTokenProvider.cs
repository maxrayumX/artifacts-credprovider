// Copyright (c) Microsoft. All rights reserved.
//
// Licensed under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;
using NuGetCredentialProvider.Logging;
using NuGetCredentialProvider.Util;
using System.Linq;
using System.Collections.Generic;

namespace NuGetCredentialProvider.CredentialProviders.Vsts
{
    internal class MsalTokenProvider : IMsalTokenProvider
    {
        private const string NativeClientRedirect = "https://login.microsoftonline.com/common/oauth2/nativeclient";
        private readonly string authority;
        private readonly string resource;
        private readonly string clientId;
        private readonly bool brokerEnabled;
        private static MsalCacheHelper helper;
        private bool cacheEnabled = false;
        private string cacheLocation;

        internal MsalTokenProvider(string authority, string resource, string clientId, bool brokerEnabled, ILogger logger)
        {
            this.authority = authority;
            this.resource = resource;
            this.clientId = clientId;
            this.brokerEnabled = brokerEnabled;
            this.Logger = logger;

            this.cacheEnabled = EnvUtil.MsalFileCacheEnabled();
            this.cacheLocation = this.cacheEnabled ? EnvUtil.GetMsalCacheLocation() : null;
        }

        public string NameSuffix => $"with{(this.brokerEnabled ? "" : "out")} WAM broker.";

        public ILogger Logger { get; private set; }

        private async Task<MsalCacheHelper> GetMsalCacheHelperAsync()
        {
            // There are options to set up the cache correctly using StorageCreationProperties on other OS's but that will need to be tested
            // for now only support windows
            if (helper == null && this.cacheEnabled && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                this.Logger.Verbose($"Using MSAL cache at `{cacheLocation}`.");

                var fileName = Path.GetFileName(cacheLocation);
                var directory = Path.GetDirectoryName(cacheLocation);

                var builder = new StorageCreationPropertiesBuilder(fileName, directory);
                builder = builder.WithCacheChangedEvent(this.clientId, "https://login.microsoftonline.com/common");
                StorageCreationProperties creationProps = builder.Build();
                helper = await MsalCacheHelper.CreateAsync(creationProps);
            }

            return helper;
        }

        public async Task<IMsalToken> AcquireTokenWithDeviceFlowAsync(Func<DeviceCodeResult, Task> deviceCodeHandler, CancellationToken cancellationToken, ILogger logger)
        {
            var deviceFlowTimeout = EnvUtil.GetDeviceFlowTimeoutFromEnvironmentInSeconds(logger);

            CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(deviceFlowTimeout));
            var linkedCancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token).Token;
            linkedCancellationToken.ThrowIfCancellationRequested();

            var publicClient = await GetPCAAsync(withBroker: false, useLocalHost: false).ConfigureAwait(false);

            var msalBuilder = publicClient.AcquireTokenWithDeviceCode(new string[] { resource }, deviceCodeHandler);
            var result = await msalBuilder.ExecuteAsync(linkedCancellationToken);
            return new MsalToken(result);
        }

        public async Task<IMsalToken> AcquireTokenSilentlyAsync(CancellationToken cancellationToken)
        {
            IPublicClientApplication publicClient = await GetPCAAsync(this.brokerEnabled, useLocalHost: false).ConfigureAwait(false);
            var accounts = new List<IAccount>();

            string loginHint = EnvUtil.GetMsalLoginHint();
            
            accounts.AddRange(await publicClient.GetAccountsAsync());

            if (this.brokerEnabled && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                accounts.Add(PublicClientApplication.OperatingSystemAccount);
            }

            foreach (var account in accounts)
            {
                try
                {
                    string canonicalName = $"{account.Environment}\\{account.HomeAccountId}\\{account.Username}";
                    if (!string.IsNullOrEmpty(loginHint) && !loginHint.Equals(canonicalName, StringComparison.Ordinal))
                    {
                        this.Logger.Verbose($"Skipping `{canonicalName}`, because it does not match Login Hint:`{loginHint}`.");
                        continue;
                    }

                    this.Logger.Verbose($"Attempting to use identity `{canonicalName}`.");
                    var silentBuilder = publicClient.AcquireTokenSilent(new string[] { resource }, account);
                    var result = await silentBuilder.ExecuteAsync(cancellationToken);
                    return new MsalToken(result);
                }
                catch (MsalUiRequiredException e)
                { 
                    this.Logger.Verbose(e.Message);
                }
                catch (MsalServiceException e)
                {
                    this.Logger.Warning(e.Message);
                }
            }

            return null;
        }

        public async Task<IMsalToken> AcquireTokenWithUI(CancellationToken cancellationToken, ILogger logging)
        {
            var deviceFlowTimeout = EnvUtil.GetDeviceFlowTimeoutFromEnvironmentInSeconds(logging);

            CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(deviceFlowTimeout));
            var linkedCancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token).Token;
            var publicClient = await GetPCAAsync(withBroker: false, useLocalHost: true).ConfigureAwait(false);

            try
            {
                var msalBuilder = publicClient.AcquireTokenInteractive(new string[] { resource });
                msalBuilder.WithPrompt(Prompt.SelectAccount);
                msalBuilder.WithUseEmbeddedWebView(false);
                var result = await msalBuilder.ExecuteAsync(linkedCancellationToken);
                return new MsalToken(result);
            }
            catch (MsalServiceException e)
            {
                if (e.ErrorCode.Contains(MsalError.AuthenticationCanceledError))
                {
                    return null;
                }

                throw;
            }
        }

        public async Task<IMsalToken> AcquireTokenWithWindowsIntegratedAuth(CancellationToken cancellationToken)
        {
            var publicClient = await GetPCAAsync(withBroker: false, useLocalHost: false).ConfigureAwait(false);

            try
            {
                string upn = WindowsIntegratedAuthUtils.GetUserPrincipalName();
                if (upn == null)
                {
                    return null;
                }

                var builder = publicClient.AcquireTokenByIntegratedWindowsAuth(new string[] { resource});
                builder.WithUsername(upn);
                var result = await builder.ExecuteAsync(cancellationToken);

                return new MsalToken(result);
            }
            catch (MsalServiceException e)
            {
                if (e.ErrorCode.Contains(MsalError.AuthenticationCanceledError))
                {
                    return null;
                }

                throw;
            }
       }

        private async Task<IPublicClientApplication> GetPCAAsync(bool withBroker, bool useLocalHost)
        {
            var helper = await GetMsalCacheHelperAsync().ConfigureAwait(false);

            var publicClientBuilder = PublicClientApplicationBuilder.Create(this.clientId)
                .WithAuthority(this.authority)
                .WithLogging(
                    (LogLevel level, string message, bool containsPii) => {
                        if (containsPii)
                        {
                            this.Logger.Verbose($"MSAL Log ({level}): [REDACTED FOR PII]");
                        }
                        else
                        {
                            this.Logger.Verbose($"MSAL Log ({level}): {message}");

                        }
                    }
                );

            if (withBroker)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    publicClientBuilder = publicClientBuilder.WithBrokerPreview();
                }
                else
                {
                    publicClientBuilder = publicClientBuilder.WithBroker();
                }
            }

            publicClientBuilder = publicClientBuilder.WithRedirectUri(
                useLocalHost
                    ? "http://localhost"
                    : NativeClientRedirect);

            var publicClient = publicClientBuilder.Build();
            helper?.RegisterCache(publicClient.UserTokenCache);
            return publicClient;
        }
    }
}
