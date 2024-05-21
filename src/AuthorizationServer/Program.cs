using AuthorizationServer.Endpoints;
using AuthorizationServer.Extensions;

var builder = WebApplication.CreateBuilder(args);
{
    builder.Services.AddSession(options =>
    {
        options.IdleTimeout = TimeSpan.FromMinutes(5);
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
    });

    builder.AddOpenIddict();

    builder.Services.AddHttpClient("TokenApiClient", client =>
    {
        client.BaseAddress = new Uri("https://localhost:4001/");
    });

    builder.Services.AddRazorPages();

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
}

var app = builder.Build();
{
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    app.UseSession();
    
    app.UseAuthentication();

    app.MapAuthorizationEndpoints();
    app.MapApplicationEndpoints();

    app.MapRazorPages();

    app.Run();
}
