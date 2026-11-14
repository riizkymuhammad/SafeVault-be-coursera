namespace SafeVault.Api.Models;

public sealed class VaultRecord
{
    public int Id { get; set; }
    public required string OwnerId { get; set; }
    public required string Title { get; set; }
    public required string Notes { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
