namespace DotnetIdentity.VMs.RequestVM
{
    public class UserUpdateRequestVM
    {
        public string FullName { get; set; }
        public string UserName { get; set; }
        public string PhoneNumber { get; set; }
        public string Email { get; set; }
        public bool AgreeToTnC { get; set; }
        public bool Active { get; set; }
        public bool Deleted { get; set; }
    }
}
