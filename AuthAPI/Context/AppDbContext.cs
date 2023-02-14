using AuthAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Context
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }
        public DbSet<User> Users {get; set;}
        /*protected override void OnModelCreateing(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("Users");
        }*/
    }
}
