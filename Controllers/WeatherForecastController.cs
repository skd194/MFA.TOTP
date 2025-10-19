using MFA.TOTP.AppService;
using MFA.TOTP.Repository;
using Microsoft.AspNetCore.Mvc;

namespace MFA.TOTP.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IUserRepository _users;
        private readonly TotpService _totpService;

        public AuthController(IUserRepository users, TotpService totpService)
        {
            _users = users;
            _totpService = totpService;
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequest req)
        {
            // simple duplicate email check
            if (_users.GetByEmail(req.Email) != null) return BadRequest("Email already in use");

            var user = new AppUser
            {
                Id = Guid.NewGuid().ToString(),
                Email = req.Email,
                PasswordHash = req.Password // NOTE: for demo only, DO NOT store plain passwords
            };

            _users.Add(user);
            return Ok(new { userId = user.Id });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest req)
        {
            var user = _users.GetByEmail(req.Email);
            if (user == null) return Unauthorized();

            // very simple password check for demo
            if (user.PasswordHash != req.Password) return Unauthorized();

            if (!user.TwoFactorEnabled)
            {
                return Ok(new { token = "demo-token-no-2fa" });
            }

            if (string.IsNullOrEmpty(req.TotpCode))
                return Unauthorized(new { requires2fa = true, message = "TOTP required" });

            var secret = _totpService.UnprotectSecret(user.ProtectedTotpSecret);
            var ok = _totpService.ValidateTotp(secret, req.TotpCode, allowedClockDriftInSteps: 1);
            if (!ok) return Unauthorized(new { requires2fa = true, message = "Invalid TOTP code" });

            return Ok(new { token = "demo-token-with-2fa" });
        }

        public class RegisterRequest { public string Email { get; set; } public string Password { get; set; } }
        public class LoginRequest { public string Email { get; set; } public string Password { get; set; } public string TotpCode { get; set; } }
    }

    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}
