using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace DotnetIdentity.Models
{
    public class Product
    {
        [BsonId]
        //[BsonElement("_id"), BsonRepresentation(BsonType.ObjectId)]
        [BsonElement("_id")]
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool Display { get; set; }

        public bool Active { get; set; }
        public bool Deleted { get; set; }
        public Guid CreatedBy { get; set; }
        public DateTime CreatedDate { get; set; }
        public Guid? ModifiedBy { get; set; }
        public DateTime? ModifiedDate { get; set; }
    }
}
