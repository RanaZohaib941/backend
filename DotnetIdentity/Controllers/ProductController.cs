using Amazon.Runtime.Internal;
using DotnetIdentity.Models;
using DotnetIdentity.VMs;
using DotnetIdentity.VMs.RequestVM;
using DotnetIdentity.VMs.ResponseVM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DotnetIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        public ProductController(DbContext dbContext)
        {
            _dbContext = dbContext;
        }

        private DbContext _dbContext;

        [HttpGet("get")]
        [Authorize(Roles = "User")]
        public async Task<ProductResponseVM> Get([FromQuery] Guid productId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                // Update existing product
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.Id, productId),
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProduct = await _dbContext.Products.Find(filter).FirstOrDefaultAsync();

                if (existingProduct != null)
                {
                    return new ProductResponseVM
                    {
                        Data = existingProduct,
                        Success = true,
                        StatusCode = 200,
                        Message = "SUCCESS"
                    };
                }
                else
                {
                    return new ProductResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Product not found."
                    };
                }
            }
            return new ProductResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpPost("get-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> GetAll(BaseAllRequestVM request)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                // Update existing product
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));
                             //Builders<Product>.Filter.Eq(x => x.Deleted, false));

                int pageNumber = request.PageNumber >= 0 ? request.PageNumber : 0;
                int pageSize = request.PageSize > 0 ? request.PageSize : 10; // Default page size to 10 if not provided


                // Retrieve paginated results
                var existingProducts = await _dbContext.Products
                    .Find(filter)
                    .Skip(pageNumber * pageSize) // Skip the previous pages
                    .Limit(pageSize) // Limit the results to the page sizem
                    .ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    return new ProductAllResponseVM
                    {
                        Data = existingProducts,
                        Success = true,
                        StatusCode = 200,
                        Message = "SUCCESS"
                    };
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Either no products listed or products have been removed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("get-all-archived")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> GetAllArchived()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                // Update existing product
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId),
                             Builders<Product>.Filter.Eq(x => x.Deleted, true));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();
                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    return new ProductAllResponseVM
                    {
                        Data = existingProducts,
                        Success = true,
                        StatusCode = 200,
                        Message = "SUCCESS"
                    };
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "No products listed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpPost("upsert")]
        [Authorize(Roles = "User")]
        public async Task<ProductResponseVM> Upsert([FromBody] ProductUpsertRequestVM request)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                if (request.Id == null || request.Id == Guid.Empty)
                {
                    var product = new Product
                    {
                        Name = request.Name,
                        Description = request.Description,
                        Display = request.Display,

                        Active = true,
                        Deleted = false,
                        CreatedBy = userId,
                        CreatedDate = currentTime,
                    };

                    await _dbContext.Products.InsertOneAsync(product);
                    return new ProductResponseVM
                    {
                        Data = product,
                        Success = true,
                        StatusCode = 200,
                        Message = "New product added."
                    };
                }

                // Update existing product
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.Id, request.Id),
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId),
                             Builders<Product>.Filter.Eq(x => x.Deleted, false));

                var existingProduct = await _dbContext.Products.Find(filter).FirstOrDefaultAsync();

                if (existingProduct != null)
                {
                    // Update fields
                    var update = Builders<Product>.Update
                        .Set(x => x.Name, request.Name)
                        .Set(x => x.Description, request.Description)
                        .Set(x => x.Display, request.Display)
                        .Set(x => x.ModifiedBy, userId)
                        .Set(x => x.ModifiedDate, DateTime.UtcNow); // Example of updating modified date

                    var result = await _dbContext.Products.UpdateOneAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).FirstOrDefaultAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Product updated"
                        };
                    }
                }
                else
                {
                    return new ProductResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Product not found or removed"
                    };
                }
            }

            return new ProductResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("change-status")]
        [Authorize(Roles = "User")]
        public async Task<ProductResponseVM> ChangeStatus([FromQuery] Guid productId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.Id, productId),
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId),
                             Builders<Product>.Filter.Eq(x => x.Deleted, false));

                var existingProduct = await _dbContext.Products.Find(filter).FirstOrDefaultAsync();

                if (existingProduct != null)
                {
                    // Update fields
                    var update = Builders<Product>.Update
                        .Set(x => x.Active, !existingProduct.Active)
                        .Set(x => x.ModifiedBy, userId)
                        .Set(x => x.ModifiedDate, DateTime.UtcNow); // Example of updating modified date

                    var result = await _dbContext.Products.UpdateOneAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).FirstOrDefaultAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Product updated"
                        };
                    }
                }
                else
                {
                    return new ProductResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Product not found or removed"
                    };
                }
            }
            return new ProductResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };

        }

        [HttpPost("deactivate-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> DeactivateAll()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId),
                             Builders<Product>.Filter.Eq(x => x.Deleted, false));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    var update = Builders<Product>.Update
                        .Set(x => x.Active, false);

                    var result = await _dbContext.Products.UpdateManyAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductAllResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).ToListAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Products deactivated"
                        };
                    }
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Either no products listed or products have been removed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("activate-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> ActivateAll()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId),
                             Builders<Product>.Filter.Eq(x => x.Deleted, false));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    var update = Builders<Product>.Update
                        .Set(x => x.Active, true);

                    var result = await _dbContext.Products.UpdateManyAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductAllResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).ToListAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Products deactivated"
                        };
                    }
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Either no products listed or products have been removed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("archive")]
        [Authorize(Roles = "User")]
        public async Task<ProductResponseVM> UpdateProductArchiveStatus([FromQuery] Guid productId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.Id, productId),
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProduct = await _dbContext.Products.Find(filter).FirstOrDefaultAsync();

                if (existingProduct != null)
                {
                    // Update fields
                    var update = Builders<Product>.Update
                        .Set(x => x.Deleted, !existingProduct.Deleted)
                        .Set(x => x.ModifiedBy, userId)
                        .Set(x => x.ModifiedDate, DateTime.UtcNow);

                    var result = await _dbContext.Products.UpdateOneAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        var response = new ProductResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).FirstOrDefaultAsync(),
                            Success = true,
                            StatusCode = 200,
                        };
                        response.Message = response.Data.Deleted ? "Product archived" : "Producted re-added";
                        return response;
                    }
                }
                else
                {
                    return new ProductResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Product not found or already removed"
                    };
                }
            }
            return new ProductResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };

        }

        [HttpGet("archive-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> ArchiveAll()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    var update = Builders<Product>.Update
                        .Set(x => x.Deleted, true);

                    var result = await _dbContext.Products.UpdateManyAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductAllResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).ToListAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Products archived"
                        };
                    }
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "No products listed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("unarchive-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> UnarchiveAll()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    var update = Builders<Product>.Update
                        .Set(x => x.Deleted, false);

                    var result = await _dbContext.Products.UpdateManyAsync(filter, update);
                    if (result.ModifiedCount > 0)
                    {
                        return new ProductAllResponseVM
                        {
                            Data = await _dbContext.Products.Find(filter).ToListAsync(),
                            Success = true,
                            StatusCode = 200,
                            Message = "Products restored"
                        };
                    }
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "No products listed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [HttpGet("delete")]
        [Authorize(Roles = "User")]
        public async Task<ProductResponseVM> Delete([FromQuery] Guid productId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.Id, productId),
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProduct = await _dbContext.Products.Find(filter).FirstOrDefaultAsync();

                if (existingProduct != null)
                {
                    // Delete product
                    var result = await _dbContext.Products.DeleteOneAsync(filter);
                    if (result.DeletedCount > 0)
                    {
                        return new ProductResponseVM
                        {
                            Success = true,
                            StatusCode = 200,
                            Message = "Product deleted"
                        };
                    }
                }
                else
                {
                    return new ProductResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "Product not found"
                    };
                }
            }
            return new ProductResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };

        }

        [HttpGet("delete-all")]
        [Authorize(Roles = "User")]
        public async Task<ProductAllResponseVM> DeleteAll()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var filter = Builders<Product>.Filter.And(
                             Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

                var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

                if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
                {
                    var result = await _dbContext.Products.DeleteManyAsync(filter);
                    if (result.DeletedCount > 0)
                    {
                        return new ProductAllResponseVM
                        {
                            Success = true,
                            StatusCode = 200,
                            Message = $"{result.DeletedCount} products deleted"
                        };
                    }
                }
                else
                {
                    return new ProductAllResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "No products listed"
                    };
                }
            }

            return new ProductAllResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }
    }
}
