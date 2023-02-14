using AuthAPI.Context;
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
                    x => x.UserName == userObj.UserName && x.Password == userObj.Password
                    );
                if (user == null)
                {
                    return NotFound(new { Message = "User Not Found"});
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
                await _authContext.Users.AddAsync(userObj);
                await _authContext.SaveChangesAsync();
                return Ok(new { Message = "Register Successful!" });

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
