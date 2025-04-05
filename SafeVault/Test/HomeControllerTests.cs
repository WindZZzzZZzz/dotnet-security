using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SafeVault.Controllers;
using Xunit;

public class HomeControllerTests
{
    private readonly HomeController _controller;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessor;

    public HomeControllerTests()
    {
        var mockLogger = new Mock<ILogger<HomeController>>();
        var mockConfiguration = new Mock<IConfiguration>();
        mockConfiguration.Setup(config => config.GetConnectionString("DefaultConnection"))
                         .Returns("YourTestConnectionStringHere");

        _httpContextAccessor = new Mock<IHttpContextAccessor>();
        var httpContext = new DefaultHttpContext();
        _httpContextAccessor.Setup(_ => _.HttpContext).Returns(httpContext);

        _controller = new HomeController(mockLogger.Object, mockConfiguration.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            }
        };
    }

    [Fact]
    public void Login_InvalidCredentials_ShouldReturnError()
    {
        // Arrange
        string username = "invalidUser";
        string password = "wrongPassword";

        // Act
        var result = _controller.Login(username, password) as ViewResult;

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Login", result.ViewName);
        Assert.True(_controller.ModelState.ContainsKey("login"));
        Assert.Equal("Invalid username or password.", _controller.ModelState["login"].Errors[0].ErrorMessage);
    }

    [Fact]
    public void AdminDashboard_UnauthorizedAccess_ShouldReturnForbid()
    {
        // Arrange
        _httpContextAccessor.Object.HttpContext.Session.SetString("UserRole", "user");

        // Act
        var result = _controller.AdminDashboard() as ForbidResult;

        // Assert
        Assert.NotNull(result);
    }

    [Fact]
    public void AdminDashboard_AuthorizedAccess_ShouldReturnView()
    {
        // Arrange
        _httpContextAccessor.Object.HttpContext.Session.SetString("UserRole", "admin");

        // Act
        var result = _controller.AdminDashboard() as ViewResult;

        // Assert
        Assert.NotNull(result);
        Assert.Equal("AdminDashboard", result.ViewName);
    }

    [Fact]
    public void Search_ValidQuery_ShouldReturnResults()
    {
        // Arrange
        string query = "testUser";

        // Act
        var result = _controller.Search(query) as ViewResult;

        // Assert
        Assert.NotNull(result);
        Assert.Equal("SearchResults", result.ViewName);
    }

    [Fact]
    public void Search_EmptyQuery_ShouldReturnError()
    {
        // Arrange
        string query = "";

        // Act
        var result = _controller.Search(query) as ViewResult;

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Search", result.ViewName);
        Assert.True(_controller.ModelState.ContainsKey("search"));
        Assert.Equal("Search query cannot be empty.", _controller.ModelState["search"].Errors[0].ErrorMessage);
    }
}