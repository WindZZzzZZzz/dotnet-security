using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using Microsoft.Data.SqlClient;  // Use Microsoft.Data.SqlClient
using BCrypt.Net; // Install BCrypt.Net-Next NuGet package

namespace SafeVault.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly string _connectionString;

    public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
    {
        _logger = logger;
        _connectionString = configuration.GetConnectionString("DefaultConnection");
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    public ActionResult SubmitForm()
    {
        return View("WebForm");
    }

    // [HttpPost]
    public ActionResult Submit(string name, string email)
    {
        // Server-side validation
        if (string.IsNullOrWhiteSpace(name) || !System.Text.RegularExpressions.Regex.IsMatch(name.Trim(), @"^[A-Za-z0-9_]{3,20}$"))
        {
            ModelState.AddModelError("username", "Username must be alphanumeric and between 3-20 characters.");
            return View("WebForm");
        }

        if (string.IsNullOrWhiteSpace(email) || !System.Text.RegularExpressions.Regex.IsMatch(email.Trim(), @"\S+@\S+\.\S+"))
        {
            ModelState.AddModelError("email", "Invalid email format.");
            return View("WebForm");
        }

        // Insert into database using parameterized queries to avoid SQL injection
        using (var connection = new SqlConnection(_connectionString))
        {
            string query = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email)";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar).Value = name.Trim();
                command.Parameters.Add("@Email", System.Data.SqlDbType.NVarChar).Value = email.Trim();

                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        return RedirectToAction("Index");
    }

    public IActionResult Register(string username, string password, string email, string role = "user")
    {
        // Validate inputs
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(email))
        {
            ModelState.AddModelError("register", "Username, password, and email are required.");
            return View("Register");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(email.Trim(), @"\S+@\S+\.\S+"))
        {
            ModelState.AddModelError("email", "Invalid email format.");
            return View("Register");
        }

        // Hash the password before storing it
        string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

        // Insert into the database
        using (var connection = new SqlConnection(_connectionString))
        {
            string query = "INSERT INTO Users (Username, PasswordHash, Email, Role) VALUES (@Username, @PasswordHash, @Email, @Role)";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar).Value = username.Trim();
                command.Parameters.Add("@PasswordHash", System.Data.SqlDbType.NVarChar).Value = hashedPassword;
                command.Parameters.Add("@Email", System.Data.SqlDbType.NVarChar).Value = email.Trim();
                command.Parameters.Add("@Role", System.Data.SqlDbType.NVarChar).Value = role.Trim();

                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        return RedirectToAction("Login");
    }

    public IActionResult Login(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            ModelState.AddModelError("login", "Username and password are required.");
            return View("Login");
        }

        using (var connection = new SqlConnection(_connectionString))
        {
            string query = "SELECT PasswordHash, Role FROM Users WHERE Username = @Username";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar).Value = username.Trim();

                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string storedPasswordHash = reader.GetString(0);
                        string role = reader.GetString(1);

                        // Verify the password
                        if (BCrypt.Net.BCrypt.Verify(password, storedPasswordHash))
                        {
                            // Store role in session or claims
                            HttpContext.Session.SetString("UserRole", role);

                            // Login successful
                            return RedirectToAction("Dashboard");
                        }
                    }
                }
            }
        }

        // Invalid username or password
        ModelState.AddModelError("login", "Invalid username or password.");
        return View("Login");
    }

    public IActionResult Search(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            ModelState.AddModelError("search", "Search query cannot be empty.");
            return View("Search");
        }

        using (var connection = new SqlConnection(_connectionString))
        {
            string sqlQuery = "SELECT Id, Username, Email FROM Users WHERE Username LIKE @Query";
            using (var command = new SqlCommand(sqlQuery, connection))
            {
                command.Parameters.Add("@Query", System.Data.SqlDbType.NVarChar).Value = $"%{query.Trim()}%";

                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    var results = new List<User>();
                    while (reader.Read())
                    {
                        results.Add(new User
                        {
                            Id = reader.GetInt32(0),
                            Username = reader.GetString(1),
                            Email = reader.GetString(2)
                        });
                    }

                    return View("SearchResults", results);
                }
            }
        }
    }

    [AuthorizeRole("admin")]
    public IActionResult AdminDashboard()
    {
        return View();
    }
}

public class AuthorizeRoleAttribute : Attribute, IAuthorizationFilter
{
    private readonly string _role;

    public AuthorizeRoleAttribute(string role)
    {
        _role = role;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var userRole = context.HttpContext.Session.GetString("UserRole");

        if (string.IsNullOrEmpty(userRole) || userRole != _role)
        {
            context.Result = new ForbidResult();
        }
    }
}