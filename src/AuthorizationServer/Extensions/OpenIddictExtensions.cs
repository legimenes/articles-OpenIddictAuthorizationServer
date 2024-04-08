using Microsoft.EntityFrameworkCore;

namespace AuthorizationServer.Extensions;

public static class OpenIddictExtensions
{
    public static WebApplicationBuilder AddOpenIddict(this WebApplicationBuilder builder)
    {
        builder.Services
            .AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore().UseDbContext<DbContext>();
            })
            .AddServer(options =>
            {
                options.AllowClientCredentialsFlow();
                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange();
                options
                    .SetTokenEndpointUris("connect/token")
                    .SetAuthorizationEndpointUris("connect/authorize");
                options
                    .AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();
                options.DisableAccessTokenEncryption();
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
            });

        builder.Services
            .AddDbContext<DbContext>(options =>
            {
                options.UseInMemoryDatabase(nameof(DbContext));
                options.UseOpenIddict();
            });

        builder.Services.AddHostedService<DataSeeder>();

        return builder;
    }
}
