using ElevatorReport.Data.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace ElevatorReport.Web.Middlewares
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly LoginServices _loginServices;

        private IConfigurationRoot appSettings
        {
            get
            {
                return new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
            }
        }

        public JwtMiddleware(RequestDelegate next, LoginServices loginServices)
        {
            _next = next;
            _loginServices = loginServices;
        }

        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                attachUserToContext(context, token);
            else
                _loginServices.CurrentUser = null;
            await _next(context);
        }

        private void attachUserToContext(HttpContext context, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(appSettings.GetSection("SecretKey").Value);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userName = jwtToken.Claims.First(x => x.Type == "name").Value;

                // attach user to context on successful jwt validation

                _loginServices.CurrentUser = _loginServices.GetByName(userName);

                context.Items["User"] = _loginServices.CurrentUser;
            }
            catch
            {
                // do nothing if jwt validation fails
                // user is not attached to context so request won't have access to secure routes
            }
        }
    }
}
