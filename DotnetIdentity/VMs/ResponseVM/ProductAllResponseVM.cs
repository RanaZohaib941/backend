using DotnetIdentity.Models;

namespace DotnetIdentity.VMs.ResponseVM
{
    public class ProductAllResponseVM : BaseResponseVM
    {
        public List<Product>? Data { get; set; }
    }
}
