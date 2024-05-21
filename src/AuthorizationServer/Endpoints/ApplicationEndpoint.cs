using Microsoft.Extensions.Primitives;
using System.Text.Json;

namespace AuthorizationServer.Endpoints;

public static class ApplicationEndpoint
{
    public static WebApplication MapApplicationEndpoints(this WebApplication app)
    {
        app.MapGet("/callback", Callback).WithOpenApi();

        return app;
    }

    public static async Task<IResult> Callback(HttpContext httpContext, IHttpClientFactory httpClientFactory)
    {
        IEnumerable<KeyValuePair<string, StringValues>> parameters = httpContext.Request.HasFormContentType ?
            httpContext.Request.Form : httpContext.Request.Query;

        Dictionary<string, string> formData = new()
        {
            { "grant_type", "authorization_code" },
            { "code_verifier", "AVA~cbYg_UDgPYrJNJX.kMotv0x.z8nY~C23XzWq4DxEUu0cw9rWk6SwlgHgihmBoPN4.WKV0H1ui6TTL3vCWC0jyv7fYlAef3Z-y-7rgC6~0m9bb06x8FEO24LJArH4" },
            { "client_id", "test_client" },
            { "client_secret", "test_secret" },
            { "redirect_uri", "https://localhost:4001/callback" }
        };
        KeyValuePair<string, StringValues> codeParameter = parameters.First(p => p.Key == "code");
        formData.Add(codeParameter.Key, codeParameter.Value);

        HttpClient httpClient = httpClientFactory.CreateClient("TokenApiClient");
        FormUrlEncodedContent content = new(formData);
        HttpResponseMessage response = await httpClient.PostAsync("connect/token", content);

        response.EnsureSuccessStatusCode();
        string responseContent = await response.Content.ReadAsStringAsync();
        dynamic? jsonObject = JsonSerializer.Deserialize<dynamic>(responseContent);

        return Results.Json(jsonObject);
    }
}
