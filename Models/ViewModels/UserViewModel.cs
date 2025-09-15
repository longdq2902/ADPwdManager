namespace ADPasswordManager.Models.ViewModels
{
    public class UserViewModel
    {
        public string Username { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string EmailAddress { get; set; } = string.Empty;
        public bool IsPasswordNeverExpires { get; set; }
        public bool IsPasswordChangeRequired { get; set; }
    }
}