namespace DotnetIdentity.VMs
{
    public class BaseResponseVM
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; }
    }
}
