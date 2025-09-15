using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning; // Thêm using này

namespace ADPasswordManager.Services
{
    // Thêm attribute này để báo cho trình biên dịch biết lớp này chỉ hoạt động trên Windows
    [SupportedOSPlatform("windows")]
    public class ADAuthenticationService
    {
        private readonly ILogger<ADAuthenticationService> _logger;
        private readonly IConfiguration _configuration;

        public ADAuthenticationService(ILogger<ADAuthenticationService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public bool IsValid(string username, string password)
        {
            // Sửa 'string' thành 'string?' để cho phép giá trị null
            string? domain = _configuration.GetValue<string>("ADSettings:Domain");

            if (string.IsNullOrEmpty(domain))
            {
                _logger.LogError("ADSettings:Domain is not configured in appsettings.json");
                return false;
            }

            try
            {
                using (var pc = new PrincipalContext(ContextType.Domain, domain))
                {
                    _logger.LogInformation("Validating credentials for user: {Username} in domain: {Domain}", username, domain);
                    bool isValid = pc.ValidateCredentials(username, password);

                    if (isValid)
                    {
                        _logger.LogInformation("Successfully validated credentials for user: {Username}", username);
                    }
                    else
                    {
                        _logger.LogWarning("Invalid credentials for user: {Username}", username);
                    }

                    return isValid;
                }
            }
            catch (PrincipalServerDownException ex)
            {
                _logger.LogError(ex, "Could not connect to the domain controller for domain {Domain}. Please check network connectivity and domain name.", domain);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during AD authentication for user {Username}", username);
                return false;
            }
        }
    }
}