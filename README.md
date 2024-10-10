Backend API
This is a backend API built using ASP.NET Core Web API framework, connected to a MongoDB database. It includes endpoints for user management and product management,
with proper authorization and GDPR compliance.

Requirements
.NET Core SDK 6.0 or later
MongoDB 4.4 or later

Getting Started
Prerequisites
.NET Core SDK: Download and install the .NET Core SDK from the official website.
MongoDB: Download and install MongoDB from the official website.
Running MongoDB

Create a Database:
Connect to MongoDB using mongo shell or a GUI tool like MongoDB Compass.
Create 2 databases named  IdentityDb for user management and  database named ProjectDb for projects table
Update the connection strings in appsettings.json accordingly as shown below
{
  "MongoDbData": {
    "ConnectionString": "mongodb://localhost:27017",
    "IdentityDb": "IdentityDb",
    "ProjectDb": "ProjectDb"
  },

  "ConnectionString": {
    "DbConnection": "mongodb://localhost:27017"
  },


