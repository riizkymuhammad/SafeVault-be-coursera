using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeVault.Api.Data;

namespace SafeVault.Api.Tests;

public sealed class SafeVaultFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public SafeVaultFactory() => _connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = "test-only-signing-key-at-least-32-bytes-long",
                ["Jwt:Issuer"] = "SafeVault.Tests",
                ["Jwt:Audience"] = "SafeVault.Tests.Client",
                ["ConnectionStrings:SafeVault"] = "Data Source=:memory:"
            }));

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<SafeVaultDbContext>>();
            services.AddDbContext<SafeVaultDbContext>(options => options.UseSqlite(_connection));
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _connection.Dispose();
    }
}
