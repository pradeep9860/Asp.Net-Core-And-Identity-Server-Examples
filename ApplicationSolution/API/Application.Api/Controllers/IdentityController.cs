using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class IdentityController : ControllerBase
    {
        public IConfiguration Configuration { get; } 
        public IdentityController(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        [HttpGet]
        [Route("get")]
        public IActionResult Get()
        {
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        } 


        [AllowAnonymous]
        [Route("getTokenAccess")]
        public async Task<IActionResult> GetToken()
        {
            // discover endpoints from metadata
            var identityServerEndpoint = Configuration["IdentityServerEndPoint:Default"];
            var disco = await DiscoveryClient.GetAsync(identityServerEndpoint);
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
             
            } 

            // request token
            var tokenClient = new TokenClient(disco.TokenEndpoint, "client", "secret");
            var tokenResponse = await tokenClient.RequestClientCredentialsAsync("api1");

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                
            }

            return new JsonResult(tokenResponse.Json);
        }

        [AllowAnonymous]
        [Route("getTokenPassword")]
        public async Task<IActionResult> GetTokenPassword()
        {
            // discover endpoints from metadata
            var identityServerEndpoint = Configuration["IdentityServerEndPoint:Default"];
            var disco = await DiscoveryClient.GetAsync(identityServerEndpoint);
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);

            }
            // request token
            var tokenClient = new TokenClient(disco.TokenEndpoint, "ro.client", "secret");
            var tokenResponse = await tokenClient.RequestResourceOwnerPasswordAsync("alice", "password", "api1");

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error); 
            } 

            return new JsonResult(tokenResponse.Json);
        }

    }
}
