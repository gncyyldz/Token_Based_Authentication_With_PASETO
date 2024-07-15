using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Paseto;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Token_Based_Authentication_With_PASETO.Handlers
{
    public class PasetoAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        readonly PasetoHandler _pasetoHandler;
        public PasetoAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            PasetoHandler pasetoHandler) : base(options, logger, encoder)
        {
            _pasetoHandler = pasetoHandler;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return Task.FromResult(AuthenticateResult.Fail("Authorization header not found."));

            string? publicKey = null;
            if (Request.Headers.ContainsKey("PublicKey"))
                publicKey = Request.Headers["PublicKey"]
                    .ToString();

            string token = Request.Headers["Authorization"]
                .ToString()
                .Replace("Bearer ", string.Empty);


            if (publicKey is null)
            {
                if (_pasetoHandler.ValidateLocalToken(token, out PasetoToken pasetoToken))
                {
                    var _claims = pasetoToken.Payload.Select(c => new { c.Key, c.Value });
                    var _footer = pasetoToken.Footer;

                    var claims = new[] {
                    new Claim(ClaimTypes.Name, pasetoToken.Payload["name"].ToString()),
                    new Claim(ClaimTypes.Role, pasetoToken.Payload["role"].ToString())
                };
                    var identity = new ClaimsIdentity(claims, "Paseto");
                    var principal = new ClaimsPrincipal(identity);
                    var ticket = new AuthenticationTicket(principal, "Paseto");

                    return Task.FromResult(AuthenticateResult.Success(ticket));
                }
                else
                    return Task.FromResult(AuthenticateResult.Fail("Invalid token."));
            }
            else
            {
                if (_pasetoHandler.ValidatePublicToken(token, publicKey, out PasetoToken pasetoToken))
                {
                    var _claims = pasetoToken.Payload.Select(c => new { c.Key, c.Value });
                    var _footer = pasetoToken.Footer;

                    var claims = new[] {
                    new Claim(ClaimTypes.Name, pasetoToken.Payload["name"].ToString()),
                    new Claim(ClaimTypes.Role, pasetoToken.Payload["role"].ToString())
                };
                    var identity = new ClaimsIdentity(claims, "Paseto");
                    var principal = new ClaimsPrincipal(identity);
                    var ticket = new AuthenticationTicket(principal, "Paseto");

                    return Task.FromResult(AuthenticateResult.Success(ticket));
                }
                else
                    return Task.FromResult(AuthenticateResult.Fail("Invalid token."));
            }
        }
    }
}
