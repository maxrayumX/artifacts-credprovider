// Copyright (c) Microsoft. All rights reserved.
//
// Licensed under the MIT license.

using System.Collections.Generic;
using NuGetCredentialProvider.Logging;
using NuGetCredentialProvider.Util;

namespace NuGetCredentialProvider.CredentialProviders.Vsts
{
    internal class MsalBearerTokenProvidersFactory : IBearerTokenProvidersFactory
    {
        private readonly ILogger logger;
        private readonly IMsalTokenProviderFactory msalTokenProviderFactory;

        public MsalBearerTokenProvidersFactory(ILogger logger, IMsalTokenProviderFactory msalTokenProviderFactory)
        {
            this.msalTokenProviderFactory = msalTokenProviderFactory;
            this.logger = logger;
        }

        public IEnumerable<IBearerTokenProvider> Get(string authority)
        {
            if (EnvUtil.MsalAllowBrokerEnabled())
            {
                IMsalTokenProvider msalTokenProviderWithBroker = msalTokenProviderFactory.Get(authority, true, logger);
                yield return new MsalSilentBearerTokenProvider(msalTokenProviderWithBroker);
            }
            
            IMsalTokenProvider msalTokenProviderNoBroker = msalTokenProviderFactory.Get(authority, false, logger);
            yield return new MsalSilentBearerTokenProvider(msalTokenProviderNoBroker);
            yield return new MsalWindowsIntegratedAuthBearerTokenProvider(msalTokenProviderNoBroker);
            yield return new MsalUserInterfaceBearerTokenProvider(msalTokenProviderNoBroker);
            yield return new MsalDeviceCodeFlowBearerTokenProvider(msalTokenProviderNoBroker);
        }
    }
}
