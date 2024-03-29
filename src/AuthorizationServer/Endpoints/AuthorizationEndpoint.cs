using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer.Endpoints;

public static class AuthorizationEndpoints
{
    public static WebApplication MapAuthorizationEndpoints(this WebApplication app)
    {
        app.MapPost("/connect/token", Exchange).WithOpenApi();
        return app;
    }

    public static IResult Exchange(HttpContext httpContext)
    {
        OpenIddictRequest? request = httpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            string? clientId = request.ClientId;
            ClaimsIdentity identity = new(authenticationType: TokenValidationParameters.DefaultAuthenticationType);
            identity.SetClaim(Claims.Subject, clientId);
            identity.SetScopes(request.GetScopes());
            ClaimsPrincipal principal = new(identity);

            return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException("The specified grant type is not implemented.");
    }
}
