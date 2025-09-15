using ADPasswordManager.Models.Configuration;
using ADPasswordManager.Models.ViewModels;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;

namespace ADPasswordManager.Services
{
    [SupportedOSPlatform("windows")]
    public class ADManagementService
    {
        private readonly ILogger<ADManagementService> _logger;
        private readonly IConfiguration _configuration;
        private readonly DelegationSettings _delegationSettings;
        private readonly string _domain;
        private readonly string _serviceUser;
        private readonly string _servicePassword;

        public ADManagementService(ILogger<ADManagementService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;

            _domain = _configuration.GetValue<string>("ADSettings:Domain") ?? string.Empty;
            _serviceUser = _configuration.GetValue<string>("ADSettings:ServiceUser") ?? string.Empty;
            _servicePassword = _configuration.GetValue<string>("ADSettings:ServicePassword") ?? string.Empty;
            _delegationSettings = _configuration.GetSection("DelegationSettings").Get<DelegationSettings>() ?? new DelegationSettings();
        }

        public List<UserPrincipal> GetManagedUsersForAdmin(string adminUsername)
        {
            _logger.LogDebug("--- Starting GetManagedUsersForAdmin for user: {user} ---", adminUsername);
            var managedUsers = new Dictionary<string, UserPrincipal>();

            if (string.IsNullOrEmpty(_domain) || !_delegationSettings.AdminMappings.Any())
            {
                _logger.LogWarning("AD domain or DelegationMappings is not configured.");
                return new List<UserPrincipal>();
            }

            if (string.IsNullOrEmpty(_serviceUser) || string.IsNullOrEmpty(_servicePassword))
            {
                _logger.LogError("AD Service Account (ServiceUser/ServicePassword) is not configured in appsettings.json.");
                return new List<UserPrincipal>();
            }

            try
            {
                using (var context = new PrincipalContext(ContextType.Domain, _domain, _serviceUser, _servicePassword))
                {
                    var adminUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, adminUsername);
                    if (adminUser == null)
                    {
                        _logger.LogWarning("Could not find admin user '{adminUsername}' in AD.", adminUsername);
                        return new List<UserPrincipal>();
                    }

                    var adminMemberOfGroups = adminUser.GetAuthorizationGroups();
                    var adminGroupNames = new HashSet<string>(adminMemberOfGroups.Select(g => g.SamAccountName));
                    _logger.LogDebug("Admin user '{user}' is member of groups: [{groups}]", adminUsername, string.Join(", ", adminGroupNames));

                    var groupsToManage = new HashSet<string>();
                    foreach (var mapping in _delegationSettings.AdminMappings)
                    {
                        if (adminGroupNames.Contains(mapping.AdminGroup))
                        {
                            _logger.LogInformation(">>> Match found! Admin user is in '{adminGroup}'. Adding managed groups to the list.", mapping.AdminGroup);
                            foreach (var managedGroup in mapping.ManagedGroups)
                            {
                                groupsToManage.Add(managedGroup);
                            }
                        }
                    }

                    _logger.LogDebug("Final list of groups to manage: [{groups}]", string.Join(", ", groupsToManage));

                    foreach (var groupName in groupsToManage)
                    {
                        var group = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName);
                        if (group != null)
                        {
                            var members = group.GetMembers(true);
                            foreach (var member in members)
                            {
                                if (member is UserPrincipal user)
                                {
                                    if (!managedUsers.ContainsKey(user.SamAccountName))
                                    {
                                        managedUsers.Add(user.SamAccountName, user);
                                    }
                                }
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Could not find managed group '{groupName}' in AD.", groupName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while getting managed users for '{adminUsername}'.", adminUsername);
            }

            _logger.LogDebug("--- Finished GetManagedUsersForAdmin. Found {count} unique users. ---", managedUsers.Count);
            return managedUsers.Values.OrderBy(u => u.SamAccountName).ToList();
        }

        public UserViewModel? GetUserStatus(string username)
        {
            _logger.LogDebug("Getting status for user '{username}'", username);
            try
            {
                using (var context = new PrincipalContext(ContextType.Domain, _domain, _serviceUser, _servicePassword))
                {
                    var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                    if (user == null)
                    {
                        _logger.LogWarning("User '{username}' not found when trying to get status.", username);
                        return null;
                    }

                    var userViewModel = new UserViewModel
                    {
                        Username = user.SamAccountName,
                        DisplayName = user.DisplayName,
                        EmailAddress = user.EmailAddress,
                        IsPasswordNeverExpires = user.PasswordNeverExpires,
                        IsPasswordChangeRequired = (user.LastPasswordSet == null)
                    };
                    return userViewModel;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get status for user '{username}'", username);
                return null;
            }
        }

        public bool ResetUserPassword(string username, string newPassword, bool setNeverExpires, bool requireChange)
        {
            _logger.LogInformation("Attempting to reset password for user '{username}' with options: SetNeverExpires={setNeverExpires}, RequireChange={requireChange}", username, setNeverExpires, requireChange);

            try
            {
                using (var pContext = new PrincipalContext(ContextType.Domain, _domain, _serviceUser, _servicePassword))
                {
                    var userPrincipal = UserPrincipal.FindByIdentity(pContext, IdentityType.SamAccountName, username);
                    if (userPrincipal == null)
                    {
                        _logger.LogWarning("User '{username}' not found. Password reset failed.", username);
                        return false;
                    }

                    userPrincipal.SetPassword(newPassword);
                    _logger.LogDebug("Password set in memory for '{username}'.", username);

                    userPrincipal.PasswordNeverExpires = setNeverExpires;
                    _logger.LogDebug("PasswordNeverExpires set to {val} for '{username}'.", setNeverExpires, username);

                    if (requireChange)
                    {
                        userPrincipal.ExpirePasswordNow();
                        _logger.LogDebug("Password for '{username}' has been set to expire.", username);
                    }

                    userPrincipal.UnlockAccount();
                    _logger.LogDebug("Account for '{username}' has been unlocked.", username);

                    userPrincipal.Save();
                    _logger.LogInformation("Successfully saved all changes for user '{username}'.", username);

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while resetting password for '{username}'", username);
                return false;
            }
        }
    }
}