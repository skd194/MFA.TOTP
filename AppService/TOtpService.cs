using System;
using System.Text;
using OtpNet;
using QRCoder;
using Microsoft.AspNetCore.DataProtection;
using System.IO;

namespace MFA.TOTP.AppService
{
    public class TotpService
    {
        private readonly IDataProtector _protector;

        // issuer - your app name shown in Google Authenticator
        public TotpService(IDataProtectionProvider dataProtectionProvider)
        {
            _protector = dataProtectionProvider.CreateProtector("TotpService.v1");
        }

        // Generate a new random secret (base32)
        public string GenerateSecret(int bytes = 20)
        {
            var key = KeyGeneration.GenerateRandomKey(bytes); // raw bytes
            return Base32Encoding.ToString(key); // base32 string
        }

        // Create otpauth:// URI (used by authenticator apps)
        // account is typically user's email or username
        // issuer is app name
        public string GenerateOtpAuthUri(string secretBase32, string account, string issuer)
        {
            // Use URL encoded label: issuer:account
            var label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}";
            var secret = secretBase32; // base32 secret
                                       // default digits=6, algorithm=SHA1, period=30
            return $"otpauth://totp/{label}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";
        }

        // Generate QR code PNG as Base64 string for embedding in <img src="data:image/png;base64,...">
        public string GenerateQrCodeBase64(string otpAuthUri, int pixelsPerModule = 6)
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrData = qrGenerator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrData);
            var bytes = qrCode.GetGraphic(pixelsPerModule);
            return Convert.ToBase64String(bytes);
        }

        // Verify TOTP code (with allowed clock drift window)
        public bool ValidateTotp(string secretBase32, string code, int allowedClockDriftInSteps = 1)
        {
            // decode secret
            var secretBytes = Base32Encoding.ToBytes(secretBase32);
            var totp = new Totp(secretBytes, step: 30, totpSize: 6); // 30s, 6 digits
                                                                     // VerifyTotp accepts window (previous/next). Otp.NET has Verify method
                                                                     // We'll check manually across window to be explicit:
            long timeStepMatched;
            return totp.VerifyTotp(code.Trim(), out timeStepMatched, new VerificationWindow(previous: allowedClockDriftInSteps, future: allowedClockDriftInSteps));
        }

        // Encrypt secret before storing
        public string ProtectSecret(string secretBase32)
        {
            return _protector.Protect(secretBase32);
        }

        // Decrypt secret from store
        public string UnprotectSecret(string protectedSecret)
        {
            return _protector.Unprotect(protectedSecret);
        }
    }
}