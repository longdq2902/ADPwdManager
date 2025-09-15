using Microsoft.EntityFrameworkCore;
using Serilog;

// Cấu hình logger của Serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/ad-password-manager-.txt", rollingInterval: RollingInterval.Day) // Ghi log ra file, mỗi ngày 1 file
    .CreateBootstrapLogger();

Log.Information("Starting up the application");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Bảo với host sử dụng Serilog thay vì logger mặc định
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .WriteTo.Console()
        .WriteTo.File("logs/ad-password-manager-.txt", rollingInterval: RollingInterval.Day)); // <-- Thêm dòng này
        

    // Add services to the container.
    // Lấy ra DbContext connection string
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
    // Cấu hình DbContext
    builder.Services.AddDbContext<ADPasswordManager.Data.ApplicationDbContext>(options =>
        options.UseSqlServer(connectionString));
    builder.Services.AddDatabaseDeveloperPageExceptionFilter();
    // Cấu hình Identity
    builder.Services.AddDefaultIdentity<Microsoft.AspNetCore.Identity.IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
        .AddEntityFrameworkStores<ADPasswordManager.Data.ApplicationDbContext>();

    builder.Services.AddControllersWithViews();

    // Đăng ký ADAuthenticationService để sử dụng trong ứng dụng
    builder.Services.AddScoped<ADPasswordManager.Services.ADAuthenticationService>();

    builder.Services.AddScoped<ADPasswordManager.Services.ADManagementService>();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseMigrationsEndPoint();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }

    // Yêu cầu pipeline sử dụng Serilog để log các request HTTP
    app.UseSerilogRequestLogging();

    app.UseHttpsRedirection();
    app.UseStaticFiles();



    app.UseRouting();

    app.UseAuthentication(); // Thêm dòng này
    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
    app.MapRazorPages(); // Thêm dòng này để các trang Identity hoạt động

    app.Run();
}
catch (Exception ex)
{
    // Ghi lại lỗi nghiêm trọng nếu ứng dụng không thể khởi động
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    // Đảm bảo các log cuối cùng được ghi lại trước khi ứng dụng đóng
    Log.CloseAndFlush();
}