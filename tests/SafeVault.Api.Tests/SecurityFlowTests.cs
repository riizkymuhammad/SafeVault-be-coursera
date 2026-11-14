using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Api.Data;
using SafeVault.Api.Models;

namespace SafeVault.Api.Tests;

public sealed class SecurityFlowTests : IClassFixture<SafeVaultFactory>
{
    private readonly SafeVaultFactory _factory;
    private readonly HttpClient _client;

    public SecurityFlowTests(SafeVaultFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_RejectsInvalidEmailAndWeakPassword()
    {
        var response = await _client.PostAsJsonAsync("/auth/register", new
        {
            email = "not-an-email",
            password = "weak"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_RejectsIncorrectPassword()
    {
        var email = await RegisterUserAsync();
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            email,
            password = "Wrong-password-123!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Registration_StoresAHashInsteadOfThePlaintextPassword()
    {
        var email = await RegisterUserAsync();
        using var scope = _factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await manager.FindByEmailAsync(email);

        Assert.NotNull(user?.PasswordHash);
        Assert.NotEqual("Str0ng-Passphrase!", user!.PasswordHash);
    }

    [Fact]
    public async Task AdminDashboard_RejectsAnonymousAndRegularUsers()
    {
        var anonymousResponse = await _client.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        var email = await RegisterUserAsync();
        await LoginAsAsync(email);
        var userResponse = await _client.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, userResponse.StatusCode);
    }

    [Fact]
    public async Task ProtectedRoute_RejectsMalformedBearerToken()
    {
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-valid-jwt");
        var response = await _client.GetAsync("/records/search");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AdminDashboard_AllowsAdminRole()
    {
        var email = await RegisterUserAsync();
        using var scope = _factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await manager.FindByEmailAsync(email);
        Assert.NotNull(user);
        var result = await manager.AddToRoleAsync(user!, "Admin");
        Assert.True(result.Succeeded);

        await LoginAsAsync(email);
        var response = await _client.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Search_SqlInjectionPayloadDoesNotReturnEveryRecord()
    {
        var email = await RegisterUserAsync();
        await LoginAsAsync(email);
        await _client.PostAsJsonAsync("/records", new { title = "Checking", notes = "Salary payment" });
        await _client.PostAsJsonAsync("/records", new { title = "Savings", notes = "Emergency fund" });

        var response = await _client.GetAsync("/records/search?q=%27%20OR%201%3D1%20--");
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var records = document.RootElement;

        Assert.Equal(JsonValueKind.Array, records.ValueKind);
        Assert.Empty(records.EnumerateArray());
    }

    [Fact]
    public async Task Search_DoesNotExposeAnotherUsersRecords()
    {
        var firstUser = await RegisterUserAsync();
        await LoginAsAsync(firstUser);
        var create = await _client.PostAsJsonAsync("/records", new { title = "Private", notes = "first user's data" });
        create.EnsureSuccessStatusCode();

        var secondUser = await RegisterUserAsync();
        await LoginAsAsync(secondUser);
        var response = await _client.GetAsync("/records/search");
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Empty(document.RootElement.EnumerateArray());
    }

    [Fact]
    public async Task SearchView_HtmlEncodesUntrustedRecordContent()
    {
        var email = await RegisterUserAsync();
        await LoginAsAsync(email);
        var payload = "<script>alert('xss')</script>";
        var create = await _client.PostAsJsonAsync("/records", new { title = payload, notes = "User content" });
        create.EnsureSuccessStatusCode();

        var response = await _client.GetAsync("/records/search-view");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain(payload, html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<string> RegisterUserAsync()
    {
        var email = $"user-{Guid.NewGuid():N}@example.test";
        var response = await _client.PostAsJsonAsync("/auth/register", new
        {
            email,
            password = "Str0ng-Passphrase!"
        });
        response.EnsureSuccessStatusCode();
        return email;
    }

    private async Task LoginAsAsync(string email)
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            email,
            password = "Str0ng-Passphrase!"
        });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenDto>();
        Assert.NotNull(token?.AccessToken);
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token!.AccessToken);
    }

    private sealed record TokenDto(string AccessToken, DateTime ExpiresAtUtc);
}
