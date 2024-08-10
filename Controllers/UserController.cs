using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserManagementAPI.Models;
using UserManagementAPI.Data;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Collections;
using System.Text;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.Security;

namespace UserManagementAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _config;
        public readonly ApiContext _context;

        public UserController(IConfiguration config, ApiContext context)
        {
            _config = config;
            _context = context;
        }

        // To generate token
        private string GenerateToken(UserResponse userResponse)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,userResponse.Username),
                new Claim(ClaimTypes.Role,userResponse.Permission),
                new Claim("id", userResponse.Id.ToString())
            };
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        private string HashPassword(string password, byte[] salt)
        {
            // derive a 256-bit subkey (use HMACSHA256 with 100,000 iterations)
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));
            return hashed;
        }

        // Register user
        [HttpPost]
        public JsonResult CreateUser(UserRequest userRequest)
        {
            // Kiem tra username da ton tai hay chua?
            var userInDb = _context.Users.SingleOrDefault(u => u.Username == userRequest.Username);

            if (userInDb != null)
            {
                return new JsonResult(BadRequest("Username was existed!"));
            }

            // Tao salt
            byte[] salt = new byte[128 / 8];
            using (var rngCsp = RandomNumberGenerator.Create())
            {
                rngCsp.GetBytes(salt);
            }

            // Tao user moi
            var user = new User();
            user.Username = userRequest.Username;
            user.Password = HashPassword(userRequest.Password, salt);
            user.Name = userRequest.Name;
            user.Permission = "user";
            user.IsActive = true;
            user.Salt = Convert.ToBase64String(salt) ;

            // Luu user vao context
            _context.Users.Add(user);
            // Luu thay doi
            _context.SaveChanges();

            return new JsonResult(Created("", new UserResponse(user.Id, user.Username, user.Name, user.Permission, "")));

        }

        // Register admin
        // Nen duoc tao boi user admin, nhung do test nen khong the voi dang dung data in memory
        // data se bi xoa khi shut down server
        [HttpPost("admin")]
        public JsonResult CreateAdmin(UserRequest userRequest)
        {
            // Kiem tra username da ton tai hay chua?
            var userInDb = _context.Users.SingleOrDefault(u => u.Username == userRequest.Username);

            if (userInDb != null)
            {
                return new JsonResult(BadRequest("Username was existed!"));
            }

            // Tao salt
            byte[] salt = new byte[128 / 8];
            using (var rngCsp = RandomNumberGenerator.Create())
            {
                rngCsp.GetBytes(salt);
            }

            // Tao user moi
            var user = new User();
            user.Username = userRequest.Username;
            user.Password = HashPassword(userRequest.Password, salt);
            user.Name = userRequest.Name;
            user.Permission = "admin";
            user.IsActive = true;
            user.Salt = Convert.ToBase64String(salt);

            // Luu user vao context
            _context.Users.Add(user);
            // Luu thay doi
            _context.SaveChanges();

            return new JsonResult(Created("", new UserResponse(user.Id, user.Username, user.Name, user.Permission, "")));

        }

        // Login
        [HttpPost("login")]
        public JsonResult Login(UserRequest userRequest)
        {
            // Kiem tra co username trong co so du lieu khong?
            var userInDb = _context.Users.SingleOrDefault(u => u.Username == userRequest.Username);

            if (userInDb == null)
            {
                return new JsonResult(BadRequest("Username or password is incorrect!"));
            }

            // hash password
            string hashedPassword = HashPassword(userRequest.Password, Convert.FromBase64String(userInDb.Salt));

            // Kiem tra password co giong trong co so du lieu khong
            if (hashedPassword != userInDb.Password)
            {
                return new JsonResult(BadRequest("Username or password is incorrect!"));
            }

            var response = new UserResponse(userInDb.Id, userInDb.Username, userInDb.Name, userInDb.Permission, "");

            var token = GenerateToken(response);

            response.Token = token;

            return new JsonResult(Ok(response));
        }

        // Change password
        [Authorize]
        [HttpPut("{id}/password")]
        public JsonResult ChangePassword(int id, UserPasswordRequest userPasswordRequest)
        {
            // Lay user hien tai
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity == null)
            {
                return new JsonResult(BadRequest("Please login!"));
            }

            var userClaims = identity.Claims;
            var permission = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value;
            var userId = Int32.Parse(userClaims.FirstOrDefault(x => x.Type == "id")?.Value);

            // Kiem tra quyen 
            if (userId != id && permission != "admin")
            {
                return new JsonResult(Forbid());
            }

            // Kiem tra co xem co user co id nay khong?
            var userInDb = _context.Users.Find(id);

            if (userInDb == null)
            {
                return new JsonResult(NotFound());
            }

            // Kiem tra password cu
            string hashedOldPassword = HashPassword(userPasswordRequest.OldPassword, Convert.FromBase64String(userInDb.Salt));

            if (hashedOldPassword != userInDb.Password)
            {
                return new JsonResult(BadRequest("Username or password is incorrect!"));
            }

            // Tao salt moi
            // generate a 128-bit salt using a cryptographically strong random sequence of nonzero values
            byte[] salt = new byte[128 / 8];
            using (var rngCsp = RandomNumberGenerator.Create())
            {
                rngCsp.GetBytes(salt);
            }

            // Hash password moi
            string hashedNewPassword = HashPassword(userPasswordRequest.NewPassword, salt);

            userInDb.Password = hashedNewPassword;
            userInDb.Salt = Convert.ToBase64String(salt);

            // Luu lai su thay doi
            _context.SaveChanges();

            return new JsonResult(NoContent());
        }

        // Edit
        [Authorize]
        [HttpPut("{id}")]
        public JsonResult Edit(int id, User user)
        {
            // Lay user hien tai
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity == null)
            {
                return new JsonResult(BadRequest("Please login!"));
            }

            var userClaims = identity.Claims;
            var permission = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value;
            var userId = Int32.Parse(userClaims.FirstOrDefault(x => x.Type == "id")?.Value);

            // Kiem tra quyen 
            if (userId != id && permission != "admin")
            {
                return new JsonResult(Forbid());
            }

            // Kiem tra co xem co user co id nay khong?
            var userInDb = _context.Users.Find(id);

            if (userInDb == null)
              {
                return new JsonResult(NotFound());
              }

            user.Id = id;

            userInDb = user;

            // Luu lai su thay doi
            _context.SaveChanges();

            return new JsonResult(Ok(user));
        }

        // Delete
        [Authorize(Policy = "Permission")]
        [HttpDelete("{id}")]
        public JsonResult Delete(int id)
        {
            // Kiem tra co xem co user co id nay khong?
            var result = _context.Users.Find(id);

            if (result == null)
            {
                return new JsonResult(NotFound());
            }

            // Xoa user
            _context.Users.Remove(result);
            // Luu thay doi
            _context.SaveChanges();

            return new JsonResult(NoContent());
        }

        // Get All
        [Authorize(Policy = "Permission")]
        [HttpGet]
        public JsonResult GetAll()
        {
            var result = _context.Users.ToList();

            return new JsonResult(Ok(result));
        }

    }
}
