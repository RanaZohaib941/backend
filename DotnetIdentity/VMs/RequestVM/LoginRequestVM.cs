using System.ComponentModel.DataAnnotations;

namespace DotnetIdentity.VMs.RequestVM
{
    public class LoginRequestVM
    {
        [Required, DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [Required, DataType(DataType.Password)]
        public string Password { get; set; }
        public int TimeSlot { get; set; }
    }
}
