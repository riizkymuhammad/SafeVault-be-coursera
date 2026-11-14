using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Data;
using SafeVault.Api.Models;
using SafeVault.Api.Security;

var builder = WebApplication.CreateBuilder(args);
var signingKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(signingKey) || Encoding.UTF8.GetByteCount(signingKey) < 32)
    throw new InvalidOperationException("Set Jwt__SigningKey to a secret of at least 32 UTF-8 bytes.");

var issuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVault";
var audience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultClient";
var connectionString = builder.Configuration.GetConnectionString("SafeVault")
    ?? "Data Source=safevault.db";

builder.Services.AddDbContext<SafeVaultDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<SafeVaultDbContext>()
    .AddSignInManager();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = "role",
            NameClaimType = JwtRegisteredClaimNames.Sub
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddSingleton<TokenService>();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// For this learning sample only. Use EF Core migrations in a deployed application.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
    await db.Database.EnsureCreatedAsync();
    var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "User", "Admin" })
        if (!await roles.RoleExistsAsync(role))
            await roles.CreateAsync(new IdentityRole(role));

    var bootstrapEmail = builder.Configuration["BootstrapAdmin:Email"];
    var bootstrapPassword = builder.Configuration["BootstrapAdmin:Password"];
    if (!string.IsNullOrWhiteSpace(bootstrapEmail) || !string.IsNullOrWhiteSpace(bootstrapPassword))
    {
        if (string.IsNullOrWhiteSpace(bootstrapEmail) || string.IsNullOrWhiteSpace(bootstrapPassword))
            throw new InvalidOperationException("Set both BootstrapAdmin__Email and BootstrapAdmin__Password, or neither.");

        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var email = bootstrapEmail.Trim().ToLowerInvariant();
        var admin = await users.FindByEmailAsync(email);
        if (admin is null)
        {
            admin = new ApplicationUser { UserName = email, Email = email };
            var createResult = await users.CreateAsync(admin, bootstrapPassword);
            if (!createResult.Succeeded)
                throw new InvalidOperationException("Bootstrap admin could not be created: " +
                    string.Join("; ", createResult.Errors.Select(error => error.Code)));
        }
        if (!await users.IsInRoleAsync(admin, "Admin"))
        {
            var roleResult = await users.AddToRoleAsync(admin, "Admin");
            if (!roleResult.Succeeded)
                throw new InvalidOperationException("Bootstrap admin role assignment failed.");
        }
    }
}

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/auth/register", async Task<IResult> (
    RegisterRequest request,
    UserManager<ApplicationUser> users,
    RoleManager<IdentityRole> roles) =>
{
    var errors = RequestValidation.Errors(request);
    if (errors.Count != 0)
        return Results.ValidationProblem(errors);

    var email = request.Email.Trim().ToLowerInvariant();
    var user = new ApplicationUser { UserName = email, Email = email };
    var result = await users.CreateAsync(user, request.Password);
    if (!result.Succeeded)
        return Results.ValidationProblem(result.Errors
            .GroupBy(error => error.Code)
            .ToDictionary(group => group.Key, group => group.Select(error => error.Description).ToArray()));

    if (await roles.RoleExistsAsync("User"))
        await users.AddToRoleAsync(user, "User");

    return Results.Created("/auth/register", new { user.Id, user.Email });
});

app.MapPost("/auth/login", async Task<IResult> (
    LoginRequest request,
    UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn,
    TokenService tokens) =>
{
    var errors = RequestValidation.Errors(request);
    if (errors.Count != 0)
        return Results.ValidationProblem(errors);

    var email = request.Email.Trim().ToLowerInvariant();
    var user = await users.FindByEmailAsync(email);
    if (user is null)
        return Results.Unauthorized();

    var check = await signIn.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
    if (!check.Succeeded)
        return Results.Unauthorized();

    var userRoles = await users.GetRolesAsync(user);
    return Results.Ok(tokens.Create(user, userRoles));
});

app.MapPost("/records", async Task<IResult> (
    CreateRecordRequest request,
    ClaimsPrincipal principal,
    SafeVaultDbContext db) =>
{
    var errors = RequestValidation.Errors(request);
    if (errors.Count != 0)
        return Results.ValidationProblem(errors);

    var ownerId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (string.IsNullOrWhiteSpace(ownerId))
        return Results.Unauthorized();

    var record = new VaultRecord
    {
        OwnerId = ownerId,
        Title = request.Title.Trim(),
        Notes = request.Notes.Trim()
    };
    db.VaultRecords.Add(record);
    await db.SaveChangesAsync();
    return Results.Created($"/records/{record.Id}",
        new RecordResponse(record.Id, record.Title, record.Notes, record.CreatedAtUtc));
}).RequireAuthorization();

app.MapGet("/records/search", async Task<IResult> (
    string? q,
    ClaimsPrincipal principal,
    SafeVaultDbContext db) =>
{
    if (q is { Length: > 120 })
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["q"] = ["Search text must be 120 characters or fewer."] });

    var userId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (string.IsNullOrWhiteSpace(userId))
        return Results.Unauthorized();

    // EF Core translates this expression to a parameterized query; q is never concatenated into SQL.
    IQueryable<VaultRecord> query = db.VaultRecords.AsNoTracking();
    if (!principal.IsInRole("Admin"))
        query = query.Where(record => record.OwnerId == userId);
    if (!string.IsNullOrWhiteSpace(q))
        query = query.Where(record => record.Title.Contains(q) || record.Notes.Contains(q));

    var records = await query.OrderByDescending(record => record.CreatedAtUtc)
        .Select(record => new RecordResponse(record.Id, record.Title, record.Notes, record.CreatedAtUtc))
        .Take(100)
        .ToListAsync();
    return Results.Ok(records);
}).RequireAuthorization();

app.MapGet("/records/search-view", async Task<IResult> (
    string? q,
    ClaimsPrincipal principal,
    SafeVaultDbContext db) =>
{
    if (q is { Length: > 120 })
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["q"] = ["Search text must be 120 characters or fewer."] });

    var userId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (string.IsNullOrWhiteSpace(userId))
        return Results.Unauthorized();

    var query = db.VaultRecords.AsNoTracking().Where(record => record.OwnerId == userId);
    if (!string.IsNullOrWhiteSpace(q))
        query = query.Where(record => record.Title.Contains(q) || record.Notes.Contains(q));

    var records = await query.Take(100).ToListAsync();
    var html = new StringBuilder("<!doctype html><html><head><meta charset=\"utf-8\"><title>SafeVault records</title></head><body><ul>");
    foreach (var record in records)
        html.Append("<li><strong>").Append(HtmlEncoder.Default.Encode(record.Title))
            .Append("</strong>: ").Append(HtmlEncoder.Default.Encode(record.Notes)).Append("</li>");
    html.Append("</ul></body></html>");
    return Results.Content(html.ToString(), "text/html; charset=utf-8");
}).RequireAuthorization();

app.MapGet("/admin/dashboard", () => Results.Ok(new { message = "Admin access granted." }))
    .RequireAuthorization(policy => policy.RequireRole("Admin"));

app.Run();

public partial class Program { }
