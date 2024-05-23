using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace AuthorizationServer;

public class DataSeeder(IServiceProvider serviceProvider) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var serviceScope = serviceProvider.CreateScope();

        await PopulateScopesAsync(serviceScope, cancellationToken);
        await PopulateInternalAppsAsync(serviceScope, cancellationToken);
        await PopulateUsersAsync(serviceScope);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    static async ValueTask PopulateInternalAppsAsync(IServiceScope serviceScope, CancellationToken cancellationToken)
    {
        IOpenIddictApplicationManager appManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        OpenIddictApplicationDescriptor appDescriptor = new()
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            DisplayName = "App Test",
            RedirectUris = { new Uri("https://localhost:4001/callback") },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope"
            }
        };

        object? client = await appManager.FindByClientIdAsync(appDescriptor.ClientId, cancellationToken);
        if (client == null)
        {
            await appManager.CreateAsync(appDescriptor, cancellationToken);
        }
        else
        {
            await appManager.UpdateAsync(client, appDescriptor, cancellationToken);
        }
    }

    static async ValueTask PopulateScopesAsync(IServiceScope serviceScope, CancellationToken cancellationToken)
    {
        IOpenIddictScopeManager scopeManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        OpenIddictScopeDescriptor scopeDescriptor = new OpenIddictScopeDescriptor
        {
            Name = "test_scope",
            Resources = { "test_resource" }
        };

        object? scopeInstance = await scopeManager.FindByNameAsync(scopeDescriptor.Name, cancellationToken);
        if (scopeInstance == null)
        {
            await scopeManager.CreateAsync(scopeDescriptor, cancellationToken);
        }
        else
        {
            await scopeManager.UpdateAsync(scopeInstance, scopeDescriptor, cancellationToken);
        }
    }

    static async ValueTask PopulateUsersAsync(IServiceScope serviceScope)
    {
        UserManager<IdentityUser> userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        IdentityUser user = new("john.doe@email.com");
        await userManager.CreateAsync(user, "Pass@word1");
    }
}
