using ADPasswordManager.Models.ViewModels;
using ADPasswordManager.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices.AccountManagement;

namespace ADPasswordManager.Controllers
{
    [Authorize]
    public class ManagementController : Controller
    {
        private readonly ILogger<ManagementController> _logger;
        private readonly ADManagementService _adManagementService;

        public ManagementController(ILogger<ManagementController> logger, ADManagementService adManagementService)
        {
            _logger = logger;
            _adManagementService = adManagementService;
        }

        public IActionResult Index()
        {
            var adminUsername = User.Identity?.Name;
            if (string.IsNullOrEmpty(adminUsername))
            {
                return Unauthorized("Cannot determine the current user.");
            }

            var samAccountName = adminUsername.Contains('\\') ? adminUsername.Split('\\')[1] : adminUsername;

            _logger.LogInformation("Fetching managed users for admin: {admin}", samAccountName);

            List<UserPrincipal> managedUsers = _adManagementService.GetManagedUsersForAdmin(samAccountName);

            var userViewModels = managedUsers.Select(user => new UserViewModel
            {
                Username = user.SamAccountName,
                DisplayName = user.DisplayName,
                EmailAddress = user.EmailAddress,
                IsPasswordNeverExpires = user.PasswordNeverExpires,
                IsPasswordChangeRequired = (user.LastPasswordSet == null)
            }).ToList();

            return View(userViewModels);
        }

        // GET: /Management/ResetPassword?username=someuser
        public IActionResult ResetPassword(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Index");
            }

            var userStatus = _adManagementService.GetUserStatus(username);

            if (userStatus == null)
            {
                return NotFound($"User '{username}' not found.");
            }

            var model = new ResetPasswordViewModel
            {
                Username = userStatus.Username,
                SetPasswordNeverExpires = userStatus.IsPasswordNeverExpires,
                RequirePasswordChangeOnLogon = userStatus.IsPasswordChangeRequired
            };

            return View(model);
        }

        // POST: /Management/ResetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                bool isSuccess = _adManagementService.ResetUserPassword(
                    model.Username,
                    model.NewPassword,
                    model.SetPasswordNeverExpires,
                    model.RequirePasswordChangeOnLogon);

                if (isSuccess)
                {
                    TempData["SuccessMessage"] = $"Password and options for user '{model.Username}' have been updated successfully.";
                    return RedirectToAction("Index");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "An error occurred while updating the user. Please check the application logs for details.");
                }
            }

            return View(model);
        }
    }
}