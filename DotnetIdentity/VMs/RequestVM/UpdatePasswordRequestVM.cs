using System.ComponentModel.DataAnnotations;

namespace DotnetIdentity.VMs.RequestVM
{
    public class UpdatePasswordRequestVM
    {
        [Required, DataType(DataType.Password)]
        public string Password { get; set; }
        [Required, DataType(DataType.Password), Compare(nameof(Password), ErrorMessage = "Passwords do not match!")]
        public string ConfirmPassword { get; set; }
    }
}
