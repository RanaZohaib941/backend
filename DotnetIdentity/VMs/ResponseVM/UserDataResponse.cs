using DotnetIdentity.VMs.RequestVM;

namespace DotnetIdentity.VMs.ResponseVM
{
    public class UserDataResponse : UserUpdateRequestVM
    {
        public Guid Id { get; set; }
        public List<string>? Roles { get; set; }

    }
}
