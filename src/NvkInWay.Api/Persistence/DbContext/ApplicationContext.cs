using Microsoft.EntityFrameworkCore;
using NvkInWay.Api.Persistence.Entities;

namespace NvkInWay.Api.Persistence.DbContext;

internal sealed class ApplicationContext : Microsoft.EntityFrameworkCore.DbContext
{
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<UserSessionsEntity> UserSessions => Set<UserSessionsEntity>();
    public DbSet<RevokedTokenEntity> RevokedTokens => Set<RevokedTokenEntity>();
    public DbSet<UserEntity> Users => Set<UserEntity>();
    
    public ApplicationContext(DbContextOptions<ApplicationContext> options) : base(options)
    {
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.HasKey(rt => rt.Id);
            entity.HasIndex(rt => rt.Token).IsUnique();
            entity.HasIndex(rt => new { rt.UserId, rt.DeviceId });
            entity.HasIndex(rt => rt.ExpiryDate);
            
            entity.Property(rt => rt.Token).IsRequired().HasMaxLength(500);
            entity.Property(rt => rt.JwtId).IsRequired().HasMaxLength(100);
        });

        modelBuilder.Entity<UserSessionsEntity>(entity =>
        {
            entity.HasKey(us => us.Id);
            entity.HasIndex(us => new { us.UserId, us.DeviceId }).IsUnique();
            entity.HasIndex(us => us.LastActivity);
            
            entity.Property(us => us.DeviceId).IsRequired().HasMaxLength(200);
        });

        modelBuilder.Entity<RevokedTokenEntity>(entity =>
        {
            entity.HasKey(rt => rt.Id);
            
            entity.HasIndex(rt => rt.JwtId).IsUnique();
            
            entity.HasIndex(rt => rt.UserId);
            entity.HasIndex(rt => rt.ExpiryDate);
            entity.HasIndex(rt => new { rt.UserId, rt.DeviceId });
            
            entity.Property(rt => rt.JwtId).IsRequired().HasMaxLength(100);
            entity.Property(rt => rt.TokenHash).HasMaxLength(256); // Для хеша токена
            entity.Property(rt => rt.Reason).HasMaxLength(200);
            entity.Property(rt => rt.RevocationType).HasConversion<string>().HasMaxLength(50);
            
            entity.HasOne(rt => rt.User)
                .WithMany()
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        
        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.HasKey(u => u.Id);

            entity.HasIndex(u => new {u.Email, u.IsDeleted});
            entity.Property(u => u.Email).IsRequired().HasMaxLength(100);
            entity.Property(u => u.FirstName).IsRequired().HasMaxLength(200);
            entity.Property(u => u.SecondName).IsRequired().HasMaxLength(200);
            entity.Property(u => u.Age).IsRequired();
        });
    }
}