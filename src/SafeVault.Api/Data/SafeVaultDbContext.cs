using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Models;

namespace SafeVault.Api.Data;

public sealed class SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<VaultRecord> VaultRecords => Set<VaultRecord>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<VaultRecord>(entity =>
        {
            entity.Property(x => x.Title).HasMaxLength(120).IsRequired();
            entity.Property(x => x.Notes).HasMaxLength(2000).IsRequired();
            entity.HasIndex(x => new { x.OwnerId, x.CreatedAtUtc });
        });
    }
}
