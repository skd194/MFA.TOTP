using MFA.TOTP.AppService;
using MFA.TOTP.Repository;
using Microsoft.AspNetCore.Mvc;

namespace MFA.TOTP.Controllers
{
    [ApiController]
    [Route("api/2fa")]
    public class TwoFactorController : ControllerBase
    {
        private readonly TotpService _totpService;
        private readonly IUserRepository _users;

        public TwoFactorController(TotpService totpService, IUserRepository users)
        {
            _totpService = totpService;
            _users = users;
        }

        // 1) Start setup: generates a secret and returns QR image + manual code to user (do not enable yet)
        [HttpPost("setup")]
        public IActionResult Setup([FromBody] SetupRequest req)
        {
            // req.UserId or req.Email should be used to identify user who is enabling 2FA
            var user = _users.GetById(req.UserId) ?? _users.GetByEmail(req.Email);
            if (user == null) return NotFound();

            // generate secret
            var secret = _totpService.GenerateSecret();
            var otpAuthUri = _totpService.GenerateOtpAuthUri(secret, user.Email, issuer: req.Issuer ?? "MyApp");
            var qrBase64 = _totpService.GenerateQrCodeBase64(otpAuthUri);

            // store the secret temporary somewhere (or return to client to submit back when they verify).
            // Better: store an encrypted "pending" secret server-side until verification completes.
            user.ProtectedTotpSecret = _totpService.ProtectSecret(secret); // temporarily stored
            _users.Update(user);

            return Ok(new
            {
                qrCodeDataUrl = $"data:image/png;base64,{qrBase64}",
                manualEntryKey = secret // you may choose to return the plain base32 so user can manually type
            });
        }

        // 2) Verify code to enable 2FA
        [HttpPost("verify")]
        public IActionResult Verify([FromBody] VerifyRequest req)
        {
            var user = _users.GetById(req.UserId) ?? _users.GetByEmail(req.Email);
            if (user == null) return NotFound();

            if (string.IsNullOrEmpty(user.ProtectedTotpSecret))
                return BadRequest("2FA setup not initialized for user.");

            var secret = _totpService.UnprotectSecret(user.ProtectedTotpSecret);
            var ok = _totpService.ValidateTotp(secret, req.Code, allowedClockDriftInSteps: 1);
            if (!ok) return BadRequest("Invalid code.");

            // Mark 2FA enabled (persist)
            user.TwoFactorEnabled = true;
            _users.Update(user);

            // Optionally generate recovery codes here
            return Ok(new { success = true });
        }
    }

    public class SetupRequest { public string UserId { get; set; } public string Email { get; set; } public string Issuer { get; set; } }
    public class VerifyRequest { public string UserId { get; set; } public string Email { get; set; } public string Code { get; set; } }

}
