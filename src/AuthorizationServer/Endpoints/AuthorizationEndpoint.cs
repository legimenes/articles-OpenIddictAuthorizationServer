using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
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
        app.MapGet("/connect/authorize", Authorize).WithOpenApi();
        app.MapGet("/callback", Callback).WithOpenApi();

        return app;
    }

    /*
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize(HttpContext httpContext)
    {
        OpenIddictRequest? request = httpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!result.Succeeded)
        {
            return Results.Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    

                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Create a new claims principal
        var claims = new List<Claim>
        {
            // 'subject' claim which is required
            new Claim(OpenIddictConstants.Claims.Subject, result.Principal.Identity.Name),
            new Claim("some claim", "some value").SetDestinations(OpenIddictConstants.Destinations.AccessToken)
        };

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // Set requested scopes (this is not done automatically)
        claimsPrincipal.SetScopes(request.GetScopes());

        // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    */

    public static async Task<IResult> Authorize(HttpContext httpContext, IOpenIddictScopeManager scopeManager)
    {
        OpenIddictRequest? request = httpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        //TODO: Results.Challenge
        var result = await httpContext.AuthenticateAsync();


        ////////////////////////////////////////////////////////////////////////////////////////////
        ClaimsIdentity identity = new(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, "1122334455667788990");
        identity.SetClaim(Claims.Name, "JohnDoe");

        identity.SetScopes(request.GetScopes());

        IAsyncEnumerable<string>? scopeResources = scopeManager.ListResourcesAsync(identity.GetScopes());
        List<string> resources = new();
        await foreach (string resource in scopeResources)
        {
            resources.Add(resource);
        }
        identity.SetResources(resources);

        identity.SetDestinations(GetDestinations);

        ClaimsPrincipal principal = new(identity);

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    public static async Task<IResult> Exchange(HttpContext httpContext, IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
    {
        OpenIddictRequest? request = httpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            object? application = await applicationManager.FindByClientIdAsync(request.ClientId!)
                ?? throw new InvalidOperationException("The application details cannot be found in the database.");

            ClaimsIdentity identity = new (
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);
            
            identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application));
            identity.SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

            identity.SetScopes(request.GetScopes());

            IAsyncEnumerable<string>? scopeResources = scopeManager.ListResourcesAsync(identity.GetScopes());
            List<string> resources = new();
            await foreach (string resource in scopeResources)
            {
                resources.Add(resource);
            }
            identity.SetResources(resources);

            identity.SetDestinations(GetDestinations);

            ClaimsPrincipal principal = new(identity);

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException("The specified grant type is not implemented.");
    }

    public static IResult Callback(HttpContext httpContext)
    {
        return Results.Ok($"Callback{httpContext.Request.QueryString.Value}");
    }

    static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            Claims.Name or Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken]
        };
    }
}
