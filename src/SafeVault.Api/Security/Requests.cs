using System.ComponentModel.DataAnnotations;

namespace SafeVault.Api.Security;

public sealed class RegisterRequest
{
    [Required, EmailAddress, StringLength(254)]
    public string Email { get; init; } = "";

    [Required, StringLength(64, MinimumLength = 8)]
    public string Password { get; init; } = "";
}

public sealed class LoginRequest
{
    [Required, EmailAddress, StringLength(254)]
    public string Email { get; init; } = "";

    [Required, StringLength(128)]
    public string Password { get; init; } = "";
}

public sealed class CreateRecordRequest
{
    [Required, StringLength(120, MinimumLength = 1)]
    public string Title { get; init; } = "";

    [Required, StringLength(2000, MinimumLength = 1)]
    public string Notes { get; init; } = "";
}

public sealed record TokenResponse(string AccessToken, DateTime ExpiresAtUtc);
public sealed record RecordResponse(int Id, string Title, string Notes, DateTimeOffset CreatedAtUtc);

public static class RequestValidation
{
    public static Dictionary<string, string[]> Errors(object request)
    {
        var results = new List<ValidationResult>();
        var context = new ValidationContext(request);
        Validator.TryValidateObject(request, context, results, validateAllProperties: true);
        return results
            .SelectMany(result => (result.MemberNames.Any() ? result.MemberNames : ["request"])
                .Select(member => (member, message: result.ErrorMessage ?? "Invalid value.")))
            .GroupBy(x => x.member)
            .ToDictionary(group => group.Key, group => group.Select(x => x.message).ToArray());
    }
}
