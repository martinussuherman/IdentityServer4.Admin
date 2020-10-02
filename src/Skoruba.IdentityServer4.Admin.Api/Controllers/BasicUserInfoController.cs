using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
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
    [Route("[controller]")]
    [ApiController]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    [Produces("application/json", "application/problem+json")]
    [Authorize]
    public class BasicUserInfoController<TUser, TKey> : ControllerBase
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private readonly UserManager<TUser> _manager;
        private readonly AdminIdentityDbContext _context;

        public BasicUserInfoController(
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
            List<UserIdentityUserClaim> nameClaims = await _context.UserClaims
                .Where(o => o.ClaimType == JwtClaimTypes.Name)
                .ToListAsync();

            List<BasicUserInfo> result = new List<BasicUserInfo>();

            foreach (UserIdentity user in users)
            {
                result.Add(new BasicUserInfo
                {
                    UserId = user.Id,
                    Name = nameClaims.FirstOrDefault(o => o.UserId == user.Id)?.ClaimValue,
                    Email = user.Email
                });
            }

            return Ok(result);
        }

        [HttpGet("{userId}")]
        public async Task<ActionResult> Get(string userId)
        {
            string uid = GetCurrentUserId();
            string role = GetCurrentUserRole();

            if (string.IsNullOrEmpty(role) && uid != userId)
            {
                return Unauthorized();
            }

            UserIdentity user = await _context.Users
                .FirstOrDefaultAsync(o => o.Id == userId);
            UserIdentityUserClaim nameClaim = await _context.UserClaims
                .FirstOrDefaultAsync(
                    o => o.UserId == userId &&
                    o.ClaimType == JwtClaimTypes.Name);

            BasicUserInfo result = new BasicUserInfo
            {
                UserId = userId,
                Name = nameClaim?.ClaimValue,
                Email = user?.Email,
            };

            return Ok(result);
        }

        private string GetCurrentUserId()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == Subject)
                .Value;
        }

        private string GetCurrentUserRole()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == Role)?
                .Value;
        }
    }

    public class BasicUserInfo
    {
        public string UserId { get; set; }

        public string Name { get; set; }

        public string Email { get; set; }
    }
}