namespace DotnetIdentity.VMs.ResponseVM
{
    public class RegisterResponseVM : BaseResponseVM
    {
        public Guid? UserId { get; set; }
        public string? UserName { get; set; }
    }
}
