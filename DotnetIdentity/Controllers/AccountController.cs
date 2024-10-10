using Amazon.Runtime.Internal;
using DotnetIdentity.Models;
using DotnetIdentity.VMs;
using DotnetIdentity.VMs.RequestVM;
using DotnetIdentity.VMs.ResponseVM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Diagnostics.SymbolStore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace DotnetIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        public AccountController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, SignInManager<ApplicationUser> signInManager, DbContext dbContext)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _dbContext = dbContext;

        }

        private UserManager<ApplicationUser> _userManager;
        private RoleManager<ApplicationRole> _roleManager;
        private SignInManager<ApplicationUser> _signInManager;
        private DbContext _dbContext;
        #region User Data

        #endregion

        #region User Data
        [Authorize]
        [HttpGet("get")]
        public async Task<UserResponseVM> GetData()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user != null && !user.Deleted)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    return new UserResponseVM
                    {
                        Data = new UserDataResponse
                        {
                            Id = user.Id,
                            FullName = user.FullName,
                            UserName = user.UserName,
                            PhoneNumber = user.PhoneNumber,
                            Email = user.Email,
                            AgreeToTnC = user.AgreeToTnC,

                            Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                            Active = user.Active,
                            Deleted = user.Deleted,
                        },
                        Success = true,
                        StatusCode = 200,
                        Message = $"SUCCESS"
                    };
                }
                else
                {
                    return new UserResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "No data found or removed."
                    };
                }
            }
            return new UserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpGet("get-user")]
        public async Task<UserResponseVM> GetUserData([FromQuery] Guid userIdRequest)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userIdRequest.ToString());
                if (user != null)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    return new UserResponseVM
                    {
                        Data = new UserDataResponse
                        {
                            Id = user.Id,
                            FullName = user.FullName,
                            UserName = user.UserName,
                            PhoneNumber = user.PhoneNumber,
                            Email = user.Email,
                            AgreeToTnC = user.AgreeToTnC,

                            Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                            Active = user.Active,
                            Deleted = user.Deleted,
                        },
                        Success = true,
                        StatusCode = 200,
                        Message = $"SUCCESS"
                    };
                }
                else
                {
                    return new UserResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "No user found"
                    };
                }
            }
            return new UserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpGet("get-all-users")]
        public async Task<AllUserResponseVM> GetAllData()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var users = await _userManager.GetUsersInRoleAsync("User");
                if (users != null && users.Count() > 0 && users.Any())
                {
                    var data = users.ToList().Select(user =>
                    {
                        var userRoles = _userManager.GetRolesAsync(user).Result;
                        return new UserDataResponse
                        {
                            Id = user.Id,
                            FullName = user.FullName,
                            UserName = user.UserName,
                            PhoneNumber = user.PhoneNumber,
                            Email = user.Email,
                            AgreeToTnC = user.AgreeToTnC,

                            Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                            Active = user.Active,
                            Deleted = user.Deleted,
                        };
                    }).ToList();

                    return new AllUserResponseVM
                    {
                        Data = data,
                        Success = true,
                        StatusCode = 200,
                        Message = $"SUCCESS"
                    };
                }
                else
                {
                    return new AllUserResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "No data found or removed."
                    };
                }
            }
            return new AllUserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize]
        [HttpGet("archive")]
        public async Task<UserResponseVM> ArchiveAccount()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user != null)
                {
                    user.Deleted = !user.Deleted;
                    var updatedUser = await _userManager.UpdateAsync(user);
                    if (updatedUser != null)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);
                        return new UserResponseVM
                        {
                            Data = new UserDataResponse
                            {
                                Id = user.Id,
                                FullName = user.FullName,
                                UserName = user.UserName,
                                PhoneNumber = user.PhoneNumber,
                                Email = user.Email,
                                AgreeToTnC = user.AgreeToTnC,

                                Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                                Active = user.Active,
                                Deleted = user.Deleted,
                            },
                            Success = true,
                            StatusCode = 200,
                            Message = $"SUCCESS"
                        };
                    }
                    return new UserResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = "Failed to update account."
                    };
                }
                else
                {
                    return new UserResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "No user found"
                    };
                }
            }
            return new UserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpGet("archive-user")]
        public async Task<UserResponseVM> ArchiveAccount([FromQuery] Guid requestUserId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(requestUserId.ToString());
                if (user != null)
                {
                    user.Deleted = !user.Deleted;
                    var updatedUser = await _userManager.UpdateAsync(user);
                    if (updatedUser != null)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);
                        return new UserResponseVM
                        {
                            Data = new UserDataResponse
                            {
                                Id = user.Id,
                                FullName = user.FullName,
                                UserName = user.UserName,
                                PhoneNumber = user.PhoneNumber,
                                Email = user.Email,
                                AgreeToTnC = user.AgreeToTnC,

                                Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                                Active = user.Active,
                                Deleted = user.Deleted,
                            },
                            Success = true,
                            StatusCode = 200,
                            Message = $"SUCCESS"
                        };
                    }
                    return new UserResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = "Failed to update account."
                    };
                }
                else
                {
                    return new UserResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "No user found"
                    };
                }
            }
            return new UserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize]
        [HttpGet("delete")]
        public async Task<BoolResponseVM> DeleteAccount()
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user != null)
                {
                    var userDeleted = await _userManager.DeleteAsync(user);
                    if (userDeleted != null && userDeleted.Succeeded)
                    {
                        var dataDeleted = await this.DeleteUserData(userId);
                        if (dataDeleted)
                        {
                            return new BoolResponseVM
                            {
                                Data = true,
                                Success = true,
                                StatusCode = 200,
                                Message = "SUCCESS"
                            };
                        }
                        return new BoolResponseVM
                        {
                            Data = false,
                            Success = false,
                            StatusCode = 409,
                            Message = "Account deleted but data deletion failed."
                        };
                    }
                    return new BoolResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = "Account deletion failed"
                    };
                }
                else
                {
                    return new BoolResponseVM
                    {
                        Success = false,
                        StatusCode = 404,
                        Message = "No user found"
                    };
                }
            }
            return new BoolResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize]
        [HttpGet("delete-user")]
        public async Task<BoolResponseVM> DeleteUserAccount([FromQuery] Guid requestUserId)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(requestUserId.ToString());
                if (user != null)
                {
                    var userDeleted = await _userManager.DeleteAsync(user);
                    if (userDeleted != null && userDeleted.Succeeded)
                    {
                        var dataDeleted = await this.DeleteUserData(requestUserId);
                        if (dataDeleted)
                        {
                            return new BoolResponseVM
                            {
                                Data = true,
                                Success = true,
                                StatusCode = 200,
                                Message = "SUCCESS"
                            };
                        }
                        return new BoolResponseVM
                        {
                            Data = false,
                            Success = false,
                            StatusCode = 409,
                            Message = "Account deleted but data deletion failed."
                        };
                    }
                }
                return new BoolResponseVM
                {
                    Success = false,
                    StatusCode = 404,
                    Message = "No user found"
                };
            }
            return new BoolResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }

        [Authorize]
        [HttpPost("update")]
        public async Task<UserResponseVM> UpdateData([FromBody] UserUpdateRequestVM requestVM)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                user.FullName = requestVM.FullName;
                user.UserName = requestVM.PhoneNumber;
                user.PhoneNumber = user.PhoneNumber;
                user.Email = user.Email;
                user.AgreeToTnC = user.AgreeToTnC;
                user.Active = user.Active;
                user.Deleted = user.Deleted;

                var updatedUser = await _userManager.UpdateAsync(user);
                if (updatedUser != null && updatedUser.Succeeded)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    return new UserResponseVM
                    {
                        Data = new UserDataResponse
                        {
                            Id = user.Id,
                            FullName = user.FullName,
                            UserName = user.UserName,
                            PhoneNumber = user.PhoneNumber,
                            Email = user.Email,
                            AgreeToTnC = user.AgreeToTnC,

                            Roles = userRoles != null && userRoles.Count() > 0 && userRoles.Any() ? userRoles.ToList() : null,

                            Active = user.Active,
                            Deleted = user.Deleted,
                        },
                        Success = true,
                        StatusCode = 200,
                        Message = $"SUCCESS"
                    };
                }

                return new UserResponseVM
                {
                    Success = false,
                    StatusCode = 500,
                    Message = "FAILED"
                };
            }
            return new UserResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }
        #endregion

        #region Identity
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<LoginResponseVM> Login(LoginRequestVM request)
        {
            //var headerToken = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            //// Validate and decode the token
            //var handler = new JwtSecurityTokenHandler();
            //var jwtToken = handler.ReadToken(headerToken) as JwtSecurityToken;

            //// Extract the roles from the token claims
            //var headerRoles = jwtToken?.Claims
            //    .Where(c => c.Type == ClaimTypes.Role)
            //    .Select(c => c.Value)
            //    .ToList();

            try
            {
                // Check if the username is correct
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    return new LoginResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 404,
                        Message = "Invalid user name"
                    };
                }

                //if (!user.Active || user.Deleted)
                //{
                //    return new LoginResponseVM
                //    {
                //        Data = null,
                //        Success = false,
                //        StatusCode = 404,
                //        Message = "User removed or archived"
                //    };
                //}

                // Check if the password is correct
                var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
                if (!isPasswordValid)
                {
                    return new LoginResponseVM
                    {
                        Data = null,
                        Success = false,
                        StatusCode = 403,
                        Message = "Invalid password"
                    };
                }

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Timeslot", request.TimeSlot.ToString())
                };

                var roles = await _userManager.GetRolesAsync(user);
                if (roles != null && roles.Count() > 0)
                {
                    var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x));
                    claims.AddRange(roleClaims);
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("A very strong key that is at least 32 characters long!"));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.UtcNow.AddHours(1); // It's a good practice to use UTC

                var token = new JwtSecurityToken(
                    issuer: "https://localhost:5001",
                    audience: "https://localhost:5001",
                    claims: claims,
                    expires: expires,
                    signingCredentials: credentials
                );

                // Use JwtSecurityTokenHandler to write the token as a string
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenString = tokenHandler.WriteToken(token); // Get the token string

                return new LoginResponseVM
                {
                    Data = tokenString, // Return the entire token as a string
                    Success = true,
                    StatusCode = 200,
                    Message = "Login successful"
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"AccountController: Login: FAILED: {ex.Message}");
            }
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<RegisterResponseVM> RegisterUser(RegisterRequestVM request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user != null)
                {
                    return new RegisterResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = "Email already registered"
                    };
                }

                user = await _userManager.FindByNameAsync(request.PhoneNumber);
                if (user != null)
                {
                    return new RegisterResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = "Please try a different username."
                    };
                }

                user = new ApplicationUser
                {
                    FullName = request.FullName,
                    PhoneNumber = request.PhoneNumber,
                    Email = request.Email,

                    NormalizedEmail = request.Email.ToUpper(),
                    NormalizedUserName = request.PhoneNumber,
                    UserName = request.PhoneNumber,

                    LockoutEnabled = true,

                    CreatedBy = Guid.Empty,
                    CreatedDate = DateTime.Now,
                    Active = true,
                    Deleted = false,
                };

                var passwordValidator = _userManager.PasswordValidators.FirstOrDefault();
                var passwordValidation = await passwordValidator!.ValidateAsync(_userManager, user, request.Password);
                if (passwordValidation == null || !passwordValidation.Succeeded)
                {
                    return new RegisterResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = $"Invalid password. {passwordValidation?.Errors?.FirstOrDefault()?.Description}"
                    };
                }


                var hashedPassword = _userManager.PasswordHasher.HashPassword(user, request.Password);
                user.PasswordHash = hashedPassword;

                var createdUser = await _userManager.CreateAsync(user);
                if (createdUser == null || !createdUser.Succeeded)
                {
                    return new RegisterResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = $"Failed to create new user. {createdUser?.Errors?.FirstOrDefault()?.Description}"
                    };
                }

                var addRoleResult = await _userManager.AddToRoleAsync(user, "User");
                if (addRoleResult == null || !addRoleResult.Succeeded)
                {
                    return new RegisterResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = $"Registration completed but failed to assign role."
                    };
                }

                return new RegisterResponseVM
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Success = true,
                    StatusCode = 200,
                    Message = $"Registration success. Please wait untill a role is assigned to your account."
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"AccountController: RegisterUser: FAILED: {ex.Message}");
            }
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpPost("CreateRole")]
        public async Task<BaseResponseVM> CreateRole(AddRoleRequestVM requestVM)
        {
            var role = await _roleManager.FindByNameAsync(requestVM.RoleName.Trim());
            if (role != null)
            {
                return new BaseResponseVM
                {
                    StatusCode = 500,
                    Success = false,
                    Message = $"A role with {requestVM.RoleName} already exists."
                };
            }

            role = new ApplicationRole
            {
                Name = requestVM.RoleName.Trim(),
                NormalizedName = requestVM.RoleName.Trim().ToUpper(),

                CreatedBy = Guid.Empty,
                CreatedDate = DateTime.Now,
                Active = true,
                Deleted = false,

            };

            var createRole = await _roleManager.CreateAsync(role);
            if (createRole == null || !createRole.Succeeded)
            {
                return new BaseResponseVM
                {
                    StatusCode = 500,
                    Success = false,
                    Message = $"Role creation failed. {createRole?.Errors?.FirstOrDefault()?.Description}"
                };
            }

            return new BaseResponseVM
            {
                StatusCode = 200,
                Success = true,
                Message = $"Success"
            };
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpGet("get-roles")]
        public List<ApplicationRole> GetRoles()
        {
            return _roleManager.Roles.ToList();
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpPost("assign-user-role")]
        public async Task<BaseResponseVM> AssignUserRole(UserRoleRequestVM requestVM)
        {

            var role = await _roleManager.FindByIdAsync(requestVM.RoleId.ToString());
            if (role == null)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"Role not found"
                };
            }
            if (!role.Active || role.Deleted)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"Role has been deactivated or archived"
                };
            }

            var user = await _userManager.FindByIdAsync(requestVM.UserId.ToString());
            if (user == null)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"User not found"
                };
            }
            if (!user.Active || user.Deleted)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"User has been deactivated or archived"
                };
            }

            var addRoleResult = await _userManager.AddToRoleAsync(user, role.Name);
            if (addRoleResult == null || !addRoleResult.Succeeded)
            {
                return new BaseResponseVM
                {
                    Success = false,
                    StatusCode = 500,
                    Message = $"Failed to assign role to user {addRoleResult?.Errors?.FirstOrDefault()?.Description}"
                };
            }

            return new BaseResponseVM
            {
                StatusCode = 200,
                Success = false,
                Message = $"Role assigned to user."
            };
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpPost("remove-user-role")]
        public async Task<BaseResponseVM> RemoveUserRole(UserRoleRequestVM requestVM)
        {

            var role = await _roleManager.FindByIdAsync(requestVM.RoleId.ToString());
            if (role == null)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"Role not found"
                };
            }
            if (!role.Active || role.Deleted)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"Role has been deactivated or archived"
                };
            }

            var user = await _userManager.FindByIdAsync(requestVM.UserId.ToString());
            if (user == null)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"User not found or archived"
                };
            }
            if (!user.Active || user.Deleted)
            {
                return new BaseResponseVM
                {
                    StatusCode = 404,
                    Success = false,
                    Message = $"User has been deactivated"
                };
            }

            var addRoleResult = await _userManager.RemoveFromRoleAsync(user, role.Name);
            if (addRoleResult == null || !addRoleResult.Succeeded)
            {
                return new BaseResponseVM
                {
                    Success = false,
                    StatusCode = 500,
                    Message = $"Failed to remove role from user {addRoleResult?.Errors?.FirstOrDefault()?.Description}"
                };
            }

            return new BaseResponseVM
            {
                StatusCode = 200,
                Success = false,
                Message = $"Role remover from user."
            };
        }

        [Authorize]
        [HttpPost("update-password")]
        public async Task<BoolResponseVM> UpdatePassword(UpdatePasswordRequestVM requestVM)
        {
            DateTime currentTime = DateTime.UtcNow;
            var headerUserId = User.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
            if (headerUserId != null && Guid.TryParse(headerUserId, out var userId))
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());

                var passwordValidator = _userManager.PasswordValidators.FirstOrDefault();
                var passwordValidation = await passwordValidator!.ValidateAsync(_userManager, user!, requestVM.Password);
                if (passwordValidation == null || !passwordValidation.Succeeded)
                {
                    return new BoolResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = $"Invalid password. {passwordValidation?.Errors?.FirstOrDefault()?.Description}"
                    };
                }

                var hashedPassword = _userManager.PasswordHasher.HashPassword(user, requestVM.Password);
                user.PasswordHash = hashedPassword;

                var updatedUser = await _userManager.UpdateAsync(user);
                if (updatedUser == null || !updatedUser.Succeeded)
                {
                    return new BoolResponseVM
                    {
                        Success = false,
                        StatusCode = 500,
                        Message = $"FAILED. {updatedUser?.Errors?.FirstOrDefault()?.Description}"
                    };
                }
                return new BoolResponseVM
                {
                    Data = true,
                    Success = true,
                    StatusCode = 200,
                    Message = $"SUCCESS"
                };
            }
            return new BoolResponseVM
            {
                Success = false,
                StatusCode = 401,
                Message = "UNAUTHORIZED"
            };
        }
        #endregion

        #region PRIVATE FUNCTIONS
        private async Task<bool> DeleteUserData(Guid userId)
        {
            var filter = Builders<Product>.Filter.And(
                         Builders<Product>.Filter.Eq(x => x.CreatedBy, userId));

            var existingProducts = await _dbContext.Products.Find(filter).ToListAsync();

            if (existingProducts != null && existingProducts.Count() > 0 && existingProducts.Any())
            {
                var result = await _dbContext.Products.DeleteManyAsync(filter);
                return result.DeletedCount > 0;
            }
            return true;
        }
        #endregion
    }
}
