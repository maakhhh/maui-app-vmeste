using Microsoft.EntityFrameworkCore;
using NvkInWay.Api.Persistence.Converters;
using NvkInWay.Api.Persistence.Entities;

namespace NvkInWay.Api.Persistence.DbContext;

internal sealed class ApplicationContext : Microsoft.EntityFrameworkCore.DbContext
{
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<UserSessionsEntity> UserSessions => Set<UserSessionsEntity>();
    public DbSet<RevokedTokenEntity> RevokedTokens => Set<RevokedTokenEntity>();
    public DbSet<UserVerificationEntity> Verifications => Set<UserVerificationEntity>();
    
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<DriveEntity> Drives => Set<DriveEntity>();
    
    public ApplicationContext(DbContextOptions<ApplicationContext> options) : base(options)
    {
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>()
            .HaveConversion<DateTimeOffsetToUtcConverter>();
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
            entity.Property(us => us.Id)
                .ValueGeneratedOnAdd();
            
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

        modelBuilder.Entity<DriveEntity>(entity =>
        {
            entity.HasKey(d => d.Id);
            
            entity.Property(u => u.From).IsRequired().HasMaxLength(200);
            entity.Property(u => u.To).IsRequired().HasMaxLength(200);
            entity.Property(u => u.Start).IsRequired();
            entity.Property(u => u.End).IsRequired();

            entity.HasOne(d => d.Driver)
                .WithMany();

            entity.HasMany(d => d.Passengers)
                .WithMany();
        });

        modelBuilder.Entity<UserVerificationEntity>(entity =>
        {
            entity.HasKey(u => u.Id);

            entity.Property(v => v.UnconfirmedEmail).HasMaxLength(100);
            entity.Property(v => v.UnconfirmedEmailCode).HasMaxLength(10);
            entity.Property(v => v.VerificationCode).HasMaxLength(10);

            entity.HasOne(v => v.User)
                .WithMany();
            
            entity.HasIndex(v => new { v.UnconfirmedEmailCode, UnconfirmedEmailCodeExpirationAt = v.VerificationCodeExpiredAt });
            entity.HasIndex(v => new { v.UserId, UnconfirmedEmailCodeCreatedAt = v.VerificationCodeCreatedAt });
        });
    }
}