using DotnetIdentity.Models;
using MongoDB.Driver;

namespace DotnetIdentity
{

    public class DbContext
    {
        public DbContext(IConfiguration configuration)
        {
            _configuration = configuration;

            // Retrieve the connection string and database names from appsettings.json
            var connectionString = _configuration["MongoDbData:ConnectionString"];
            var identityDb = _configuration["MongoDbData:IdentityDb"];
            var projectDb = _configuration["MongoDbData:ProjectDb"];

            // Create a MongoClient and get the databases
            var mongoClient = new MongoClient(connectionString);
            _identityDatabase = mongoClient.GetDatabase(identityDb);
            _projectDatabase = mongoClient.GetDatabase(projectDb);

            Products = _projectDatabase.GetCollection<Product>("Products");
        }
        private readonly IConfiguration _configuration;


        private readonly IMongoDatabase _identityDatabase;
        private readonly IMongoDatabase _projectDatabase;

        public IMongoCollection<Product> Products { get; }
    }

}
