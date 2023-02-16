using AuthAPI.Context;
using AuthAPI.Helpers;
using AuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
 
                return Ok(new { Message = "Loggin Successful!" });

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
 
    }
}
