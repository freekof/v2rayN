using ServiceLib.Models.Dto;
using Xunit;

namespace ServiceLib.Tests.Models;

public class ProfileItemModelTests
{
    [Fact]
    public void Remarks_RaisesPropertyChanged()
    {
        var item = new ProfileItemModel();
        string? changedProperty = null;
        item.PropertyChanged += (_, args) => changedProperty = args.PropertyName;

        item.Remarks = "US1.1.1.1 AS13335";

        Assert.Equal(nameof(ProfileItemModel.Remarks), changedProperty);
    }
}
