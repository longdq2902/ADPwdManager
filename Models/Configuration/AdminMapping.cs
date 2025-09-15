namespace ADPasswordManager.Models.Configuration
{
    public class AdminMapping
    {
        public string AdminGroup { get; set; } = string.Empty;
        public List<string> ManagedGroups { get; set; } = new();
    }
}