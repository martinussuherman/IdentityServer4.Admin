using System.ComponentModel.DataAnnotations;

namespace Skoruba.IdentityServer4.STS.Identity.ViewModels.Account
{
    public class ResendConfirmationEmailViewModel
    {
        [EmailAddress]
        public string Email { get; set; }

        public string Username { get; set; }
    }
}
