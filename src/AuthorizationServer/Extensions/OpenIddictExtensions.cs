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
                options.SetTokenEndpointUris("connect/token");
                options.AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();
                options.DisableAccessTokenEncryption();
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough();
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
