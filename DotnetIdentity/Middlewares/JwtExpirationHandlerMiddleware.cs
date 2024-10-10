using DotnetIdentity.VMs;
using System.Text.Json;

namespace DotnetIdentity.Middlewares
{
    public class JwtExpirationHandlerMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtExpirationHandlerMiddleware> _logger;

        public JwtExpirationHandlerMiddleware(RequestDelegate next, ILogger<JwtExpirationHandlerMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Call the next middleware in the pipeline
            await _next(context);

            async Task WriteResponseAsync(BaseResponseVM response)
            {
                context.Response.ContentType = "application/json";
                var jsonResponse = JsonSerializer.Serialize(response);
                await context.Response.WriteAsync(jsonResponse);
            }

            // Check if the response status code is 401 (Unauthorized)
            if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
            {
                // Log the expiration event
                _logger.LogWarning("JWT token has expired or is invalid.");

                // Response
                var response = new BaseResponseVM
                {
                    Success = false,
                    StatusCode = StatusCodes.Status403Forbidden,
                    Message = "JWT token is expired or invalid."
                };

                await WriteResponseAsync(response);
            }

            // Check if the response status code is 403 (Forbidden)
            if (context.Response.StatusCode == StatusCodes.Status403Forbidden)
            {
                // Log the expiration event
                _logger.LogWarning("Invalid access");

                // Response
                var response = new BaseResponseVM
                {
                    Success = false,
                    StatusCode = StatusCodes.Status403Forbidden,
                    Message = "Unauthorized access attempt."
                };

                await WriteResponseAsync(response);
            }
        }
    }
}
