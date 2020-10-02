using System;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Skoruba.IdentityServer4.Admin.Api.Dtos.Users;
using Skoruba.IdentityServer4.Admin.Api.ExceptionHandling;
using Skoruba.IdentityServer4.Admin.Api.Helpers.Localization;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Dtos.Identity;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services.Interfaces;

namespace PsefIdentityAdmin.Admin.Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    [Produces("application/json", "application/problem+json")]
    [Authorize]
    public class CurrentUserController<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken,
             TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto,
             TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto> : ControllerBase
         where TUserDto : UserDto<TKey>, new()
         where TRoleDto : RoleDto<TKey>, new()
         where TUser : IdentityUser<TKey>
         where TRole : IdentityRole<TKey>
         where TKey : IEquatable<TKey>
         where TUserClaim : IdentityUserClaim<TKey>
         where TUserRole : IdentityUserRole<TKey>
         where TUserLogin : IdentityUserLogin<TKey>
         where TRoleClaim : IdentityRoleClaim<TKey>
         where TUserToken : IdentityUserToken<TKey>
         where TUsersDto : UsersDto<TUserDto, TKey>
         where TRolesDto : RolesDto<TRoleDto, TKey>
         where TUserRolesDto : UserRolesDto<TRoleDto, TKey>
         where TUserClaimsDto : UserClaimsDto<TUserClaimDto, TKey>, new()
         where TUserProviderDto : UserProviderDto<TKey>
         where TUserProvidersDto : UserProvidersDto<TKey>
         where TUserChangePasswordDto : UserChangePasswordDto<TKey>
         where TRoleClaimsDto : RoleClaimsDto<TKey>
         where TUserClaimDto : UserClaimDto<TKey>
    {
        private readonly IIdentityService<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken,
            TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto,
            TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto> _identityService;
        private readonly IGenericControllerLocalizer<CurrentUserController<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken,
            TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto,
            TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto>> _localizer;

        private readonly IMapper _mapper;
        private readonly UserManager<TUser> _manager;

        public CurrentUserController(IIdentityService<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken,
                TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto,
                TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto> identityService,
            IGenericControllerLocalizer<CurrentUserController<TUserDto, TRoleDto, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken,
                TUsersDto, TRolesDto, TUserRolesDto, TUserClaimsDto,
                TUserProviderDto, TUserProvidersDto, TUserChangePasswordDto, TRoleClaimsDto, TUserClaimDto>> localizer, IMapper mapper, UserManager<TUser> manager)
        {
            _identityService = identityService;
            _localizer = localizer;
            _mapper = mapper;
            _manager = manager;
        }

        [HttpGet]
        public async Task<ActionResult<TUserDto>> Get()
        {
            var user = await _identityService.GetUserAsync(GetCurrentUserId());

            return Ok(user);
        }

        [HttpGet("Roles")]
        public async Task<ActionResult<UserRolesApiDto<TRoleDto>>> GetUserRoles(
            int page = 1,
            int pageSize = 10)
        {
            var userRoles = await _identityService.GetUserRolesAsync(
                GetCurrentUserId(),
                page,
                pageSize);

            return Ok(_mapper.Map<UserRolesApiDto<TRoleDto>>(userRoles));
        }

        [HttpGet("Claims")]
        public async Task<ActionResult<UserClaimsApiDto<TKey>>> GetUserClaims(
            int page = 1,
            int pageSize = 10)
        {
            var claims = await _identityService.GetUserClaimsAsync(
                GetCurrentUserId(),
                page,
                pageSize);

            return Ok(_mapper.Map<UserClaimsApiDto<TKey>>(claims));
        }

        [HttpGet("Providers")]
        public async Task<ActionResult<UserProvidersApiDto<TKey>>> GetUserProviders()
        {
            var userProvidersDto = await _identityService.GetUserProvidersAsync(
                GetCurrentUserId());

            return Ok(_mapper.Map<UserProvidersApiDto<TKey>>(userProvidersDto));
        }

        [HttpPost("ChangePassword")]
        public async Task<IActionResult> PostChangePassword([FromBody] ChangePasswordData data)
        {
            var user = await _manager.FindByIdAsync(GetCurrentUserId());
            var result = await _manager.ChangePasswordAsync(
                user,
                data.OldPassword,
                data.NewPassword);

            if (result.Succeeded)
            {
                return Ok();
            }

            return Unauthorized();
        }

        // [HttpGet("RoleClaims")]
        // public async Task<ActionResult<RoleClaimsApiDto<TRoleDtoKey>>> GetRoleClaims(TUserDtoKey id, string claimSearchText, int page = 1, int pageSize = 10)
        // {
        //     var roleClaimsDto = await _identityService.GetUserRoleClaimsAsync(GetCurrentUserId(), claimSearchText, page, pageSize);
        //     var roleClaimsApiDto = _mapper.Map<RoleClaimsApiDto<TRoleDtoKey>>(roleClaimsDto);

        //     return Ok(roleClaimsApiDto);
        // }

        private string GetCurrentUserId()
        {
            return HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == IdentityModel.JwtClaimTypes.Subject)
                .Value;
        }

        // private T ConvertObject<T>(object input)
        // {
        //     return (T)Convert.ChangeType(input, typeof(T));
        // }

        public class ChangePasswordData
        {
            public string OldPassword { get; set; }
            public string NewPassword { get; set; }
        }
    }
}
