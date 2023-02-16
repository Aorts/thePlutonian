using AuthAPI.Context;
using AuthAPI.Helpers;
using AuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthAPI.Controllers
{
    [Route("api/users")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UsersController(AppDbContext authContext)
        {
            _authContext = authContext;
        }
        [HttpPost]
        [Route("authen")]
        public async Task<IActionResult> Authenticate([FromBody] LoginModel userObj)
        {
            try
            {
                if(userObj == null)
                {
                    return BadRequest();
                }

                var user = await _authContext.Users.FirstOrDefaultAsync( 
                    x => x.UserName == userObj.UserName
                    );

                if (user == null || !PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                {
                    return NotFound(new { Message = "Invalid login, please try again!" });
                }

                user.Token = CreateJwt(user);

                return Ok(new { 
                    Token = user.Token,
                    Message = "Loggin Successful!" 
                });

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            try
            {
                if (userObj == null)
                {
                    return BadRequest();
                }

                if (await CheckUsernameisExiting(userObj.UserName))
                {
                    return BadRequest(new { Message = "Username Already Exit!" });
                }

                if (await CheckEmailisExiting(userObj.Email))
                {
                    return BadRequest(new { Message = "Email Already Exit!" });
                }

                userObj.Password = PasswordHasher.HashPassword(userObj.Password);
                userObj.Role = "User";
                userObj.Token = "";
                await _authContext.Users.AddAsync(userObj);
                await _authContext.SaveChangesAsync();
                return Ok(new { Message = "Register Successful!" });

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private async Task<bool> CheckUsernameisExiting(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.UserName == username);
        }
        private async Task<bool> CheckEmailisExiting(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("qOu4OiEsGNH44aNe0PF9NhZxnrETQtwLPKWWGty2OA");
            var identity = new ClaimsIdentity( new Claim[]
                {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")}
                );
            var credentails = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentails
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            string result = jwtTokenHandler.WriteToken(token);
            return result;
        }
 
    }
}
