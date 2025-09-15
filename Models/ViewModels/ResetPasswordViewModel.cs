using System.ComponentModel.DataAnnotations;

namespace ADPasswordManager.Models.ViewModels
{
    public class ResetPasswordViewModel
    {
        // Dùng để lưu trữ username, không cho người dùng sửa
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required.")]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Display(Name = "Password never expires")]
        public bool SetPasswordNeverExpires { get; set; }

        [Display(Name = "User must change password at next logon")]
        public bool RequirePasswordChangeOnLogon { get; set; }
    }
}
