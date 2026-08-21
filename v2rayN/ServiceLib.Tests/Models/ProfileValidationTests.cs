using ServiceLib.Enums;
using ServiceLib.Handler.Builder;
using ServiceLib.Models.Entities;
using AwesomeAssertions;
using Xunit;

namespace ServiceLib.Tests.Models;

public class ProfileValidationTests
{
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("Valid Remarks")]
    public void ProfileItem_WithEmptyOrNullRemarks_ShouldBeValid(string? remarks)
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Address = "127.0.0.1",
            Port = 1080,
            Password = "b26857ed-2661-4545-9831-29472e361b96",
            Remarks = remarks!
        };

        var isValid = item.IsValid();
        isValid.Should().BeTrue();

        var validationResult = NodeValidator.Validate(item, ECoreType.Xray);
        validationResult.Success.Should().BeTrue();
    }

    [Fact]
    public void ProfileItem_InvalidAddress_ShouldFailValidation()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Address = "",
            Port = 1080,
            Password = "b26857ed-2661-4545-9831-29472e361b96",
            Remarks = ""
        };

        var isValid = item.IsValid();
        isValid.Should().BeFalse();

        var validationResult = NodeValidator.Validate(item, ECoreType.Xray);
        validationResult.Success.Should().BeFalse();
    }

    [Fact]
    public void ProfileItem_InvalidPort_ShouldFailValidation()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Address = "127.0.0.1",
            Port = 0,
            Password = "b26857ed-2661-4545-9831-29472e361b96",
            Remarks = ""
        };

        var isValid = item.IsValid();
        isValid.Should().BeFalse();

        var validationResult = NodeValidator.Validate(item, ECoreType.Xray);
        validationResult.Success.Should().BeFalse();
    }

    [Fact]
    public void ProfileItem_InvalidUUID_ShouldFailValidation()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Address = "127.0.0.1",
            Port = 1080,
            Password = "not-a-valid-uuid",
            Remarks = ""
        };

        var isValid = item.IsValid();
        isValid.Should().BeFalse();

        var validationResult = NodeValidator.Validate(item, ECoreType.Xray);
        validationResult.Success.Should().BeFalse();
    }
}
