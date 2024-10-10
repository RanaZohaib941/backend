namespace DotnetIdentity.VMs.RequestVM
{
    public class ProductUpsertRequestVM
    {
        public Guid? Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool Display { get; set; }
    }
}
