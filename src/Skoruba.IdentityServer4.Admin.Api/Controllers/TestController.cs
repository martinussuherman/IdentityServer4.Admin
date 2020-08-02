using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Skoruba.IdentityServer4.Admin.Api.ExceptionHandling;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.DbContexts;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;
using static IdentityModel.JwtClaimTypes;

namespace PsefIdentityAdmin.Admin.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    [Produces("application/json", "application/problem+json")]
    [Authorize]
    public class TestController<TUser, TKey> : ControllerBase
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        public class UserInfo
        {
            public string UserId { get; set; }
            public string Username { get; set; }
            public string Email { get; set; }
            public string Role { get; set; }
        }

        public TestController(
            UserManager<TUser> manager,
            AdminIdentityDbContext context)
        {
            _manager = manager;
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult> Get()
        {
            string role = GetCurrentUserRole();

            if (string.IsNullOrEmpty(role))
            {
                return Unauthorized();
            }

            List<UserIdentity> users = await _context.Users
                .AsNoTracking()
                .ToListAsync();

            List<UserInfo> result = new List<UserInfo>();

            foreach (UserIdentity user in users)
            {
                result.Add(new UserInfo
                {
                    UserId = user.Id,
                    Username = user.UserName,
                    Email = user.Email
                });
            }

            return Ok(result);
        }

        [HttpGet("UserInfo")]
        public ActionResult GetUserInfo()
        {
            string role = GetCurrentUserRole();

            if (string.IsNullOrEmpty(role))
            {
                return Unauthorized();
            }

            UserInfo info = new UserInfo
            {
                UserId = GetCurrentUserId(),
                Username = GetCurrentUserName(),
                Email = GetCurrentUserEmail(),
                Role = role
            };

            return Ok(info);
        }

        private string GetCurrentUserId()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == Subject)
                .Value;
            // ClaimTypes.NameIdentifier
        }

        private string GetCurrentUserName()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == PreferredUserName)?
                .Value;
        }

        private string GetCurrentUserEmail()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == Email)?
                .Value;
        }

        private string GetCurrentUserRole()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == Role)?
                .Value;
        }

        private readonly UserManager<TUser> _manager;
        private readonly AdminIdentityDbContext _context;
    }
}