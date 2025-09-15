using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ADPasswordManager.Models;
using Microsoft.AspNetCore.Authorization;
namespace ADPasswordManager.Controllers;

[Authorize]
public class HomeController : Controller
{
    // Bước 1: Thêm một biến private để giữ logger
    private readonly ILogger<HomeController> _logger;

    // Bước 2: Sửa constructor để nhận ILogger thông qua Dependency Injection
    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        // Bước 3: Ghi một log Information
        _logger.LogInformation("User has accessed the Home page.");
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}