using OpenIddict.Abstractions;

namespace AuthorizationServer;

public class DataSeeder(IServiceProvider serviceProvider) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var serviceScope = serviceProvider.CreateScope();

        await PopulateScopes(serviceScope, cancellationToken);
        await PopulateInternalApps(serviceScope, cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    static async ValueTask PopulateInternalApps(IServiceScope serviceScope, CancellationToken cancellationToken)
    {
        IOpenIddictApplicationManager appManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        OpenIddictApplicationDescriptor appDescriptor = new()
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope"
            }
        };

        var client = await appManager.FindByClientIdAsync(appDescriptor.ClientId, cancellationToken);
        if (client == null)
        {
            await appManager.CreateAsync(appDescriptor, cancellationToken);
        }
        else
        {
            await appManager.UpdateAsync(client, appDescriptor, cancellationToken);
        }
    }

    static async ValueTask PopulateScopes(IServiceScope serviceScope, CancellationToken cancellationToken)
    {
        var scopeManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        var scopeDescriptor = new OpenIddictScopeDescriptor
        {
            Name = "test_scope",
            Resources = { "test_resource" }
        };

        var scopeInstance = await scopeManager.FindByNameAsync(scopeDescriptor.Name, cancellationToken);
        if (scopeInstance == null)
        {
            await scopeManager.CreateAsync(scopeDescriptor, cancellationToken);
        }
        else
        {
            await scopeManager.UpdateAsync(scopeInstance, scopeDescriptor, cancellationToken);
        }
    }
}
