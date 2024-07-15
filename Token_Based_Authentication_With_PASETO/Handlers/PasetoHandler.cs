using Microsoft.AspNetCore.Authentication;
using Paseto;
using Paseto.Builder;
using System.Security.Cryptography;
using System.Text;

namespace Token_Based_Authentication_With_PASETO.Handlers
{
    public class PasetoHandler(IConfiguration configuration)
    {
        public object GenerateLocalToken()
        {
            var token = new PasetoBuilder()
                .Use(ProtocolVersion.V1, Purpose.Local)
                .WithKey(Encoding.UTF8.GetBytes(configuration["Paseto:Key"]), Encryption.SymmetricKey)
                .AddClaim("name", "gncy")
                .AddClaim("role", "mod")
                .AddClaim("email", "gyildizmail@gmail.com")
                .AddFooter("tel : 05077519999")
                .AddFooter("tel2 : 12345678901")
                .Issuer("www.gencayyildiz.com")
                .Subject(Guid.NewGuid().ToString())
                .Audience("www.myapi.com")
                .NotBefore(DateTime.UtcNow.AddMinutes(5))
                .IssuedAt(DateTime.UtcNow)
                .Expiration(DateTime.UtcNow.AddHours(1))
                .TokenIdentifier("123456ABCD")
                .Encode();

            return new
            {
                Token = token
            };
        }
        public object GeneratePublicToken()
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            var privateKey = rsa.ExportRSAPrivateKey();
            var publicKey = rsa.ExportRSAPublicKey();

            var token = new PasetoBuilder()
                .Use(ProtocolVersion.V1, Purpose.Public)
                .WithKey(privateKey, Encryption.AsymmetricSecretKey)
                .AddClaim("name", "gncy")
                .AddClaim("role", "mod")
                .AddClaim("email", "gyildizmail@gmail.com")
                .AddFooter("tel : 05077519999")
                .AddFooter("tel2 : 12345678901")
                .Issuer("www.gencayyildiz.com")
                .Subject(Guid.NewGuid().ToString())
                .Audience("www.myapi.com")
                .NotBefore(DateTime.UtcNow.AddMinutes(5))
                .IssuedAt(DateTime.UtcNow)
                .Expiration(DateTime.UtcNow.AddHours(1))
                .TokenIdentifier("123456ABCD")
                .Encode();

            return new
            {
                Token = token,
                PublicKey = Convert.ToBase64String(publicKey)
            };
        }

        public PasetoToken DecodeLocalToken(string token)
        {
            var pasetoTokenValidationResult = new PasetoBuilder()
                .Use(ProtocolVersion.V1, Purpose.Local)
                .WithKey(Encoding.UTF8.GetBytes(configuration["Paseto:Key"]), Encryption.SymmetricKey)
                .Decode(token);

            var payload = pasetoTokenValidationResult.Paseto;
            return payload;
        }

        public PasetoToken DecodePublicToken(string token, string publicKey)
        {
            var pasetoTokenValidationResult = new PasetoBuilder()
                .Use(ProtocolVersion.V1, Purpose.Public)
                .WithKey(Convert.FromBase64String(publicKey), Encryption.AsymmetricPublicKey)
                .Decode(token);

            var payload = pasetoTokenValidationResult.Paseto;
            return payload;
        }

        public bool ValidateLocalToken(string token, out PasetoToken pasetoToken)
        {
            var pasetoTokenValidationResult = new PasetoBuilder()
               .Use(ProtocolVersion.V1, Purpose.Local)
               .WithKey(Encoding.UTF8.GetBytes(configuration["Paseto:Key"]), Encryption.SymmetricKey)
               .Decode(token);

            pasetoToken = pasetoTokenValidationResult.Paseto;

            return pasetoTokenValidationResult.IsValid;
        }

        public bool ValidatePublicToken(string token, string publicKey, out PasetoToken pasetoToken)
        {
            try
            {
                var pasetoTokenValidationResult = new PasetoBuilder()
                  .Use(ProtocolVersion.V1, Purpose.Public)
                  .WithKey(Convert.FromBase64String(publicKey), Encryption.AsymmetricPublicKey)
                  .Decode(token);

                pasetoToken = pasetoTokenValidationResult.Paseto;

                return pasetoTokenValidationResult.IsValid;
            }
            catch (Exception ex)
            {
                pasetoToken = null;
                return false;
            }
        }
    }
}
