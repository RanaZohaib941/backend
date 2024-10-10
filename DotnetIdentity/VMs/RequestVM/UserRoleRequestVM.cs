using System.ComponentModel.DataAnnotations;

namespace DotnetIdentity.VMs.RequestVM
{
    public class UserRoleRequestVM
    {
        [Required]
        public Guid UserId { get; set; }
        [Required]
        public Guid RoleId { get; set; }
    }
}
