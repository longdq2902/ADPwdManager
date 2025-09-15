using ADPasswordManager.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace ADPasswordManager.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly ADAuthenticationService _adAuthService;
        private readonly UserManager<IdentityUser> _userManager;

        public LoginModel(SignInManager<IdentityUser> signInManager,
                          ILogger<LoginModel> logger,
                          ADAuthenticationService adAuthService,
                          UserManager<IdentityUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _adAuthService = adAuthService;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = default!; // Sửa lỗi CS8618

        public string ReturnUrl { get; set; } = default!;

        [TempData]
        public string ErrorMessage { get; set; } = default!;

        public class InputModel
        {
            [Required]
            [Display(Name = "Username")]
            public string Email { get; set; } = default!;

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; } = default!;

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }
            returnUrl ??= Url.Content("~/Management");
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/Management");

            if (ModelState.IsValid)
            {
                var isValidADUser = _adAuthService.IsValid(Input.Email, Input.Password);

                if (isValidADUser)
                {
                    _logger.LogInformation("User {Username} authenticated successfully against AD.", Input.Email);

                    var user = await _userManager.FindByNameAsync(Input.Email);
                    if (user == null)
                    {
                        _logger.LogInformation("Local user for {Username} not found. Creating a new one.", Input.Email);
                        user = new IdentityUser { UserName = Input.Email, Email = Input.Email, EmailConfirmed = true };
                        var result = await _userManager.CreateAsync(user);
                        if (!result.Succeeded)
                        {
                            _logger.LogError("Could not create local user for {Username}", Input.Email);
                            ModelState.AddModelError(string.Empty, "Error creating local user account.");
                            return Page();
                        }
                    }

                    await _signInManager.SignInAsync(user, isPersistent: Input.RememberMe);

                    _logger.LogInformation("User {Username} logged in.", Input.Email);
                    return LocalRedirect(returnUrl);
                }
                else
                {
                    _logger.LogWarning("Invalid login attempt for user {Username}.", Input.Email);
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }
            return Page();
        }
    }
}