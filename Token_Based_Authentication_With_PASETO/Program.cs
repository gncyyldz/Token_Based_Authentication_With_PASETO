using Microsoft.AspNetCore.Authentication;
using Token_Based_Authentication_With_PASETO.Handlers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<PasetoHandler>();
builder.Services.AddAuthentication("Paseto")
    .AddScheme<AuthenticationSchemeOptions, PasetoAuthenticationHandler>("Paseto", null);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext context, PasetoHandler pasetoHandler) =>
{
    return Results.Ok();
})
    .RequireAuthorization(p => p.RequireRole("mod"));

app.MapGet("/get-local-token", (PasetoHandler pasetoHandler) =>
{
    return pasetoHandler.GenerateLocalToken();
});

app.MapGet("/get-public-token", (PasetoHandler pasetoHandler) =>
{
    return pasetoHandler.GeneratePublicToken();
});

app.Run();