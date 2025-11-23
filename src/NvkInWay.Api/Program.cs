using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NvkInWay.Api.Authorization;
using NvkInWay.Api.Persistence;
using NvkInWay.Api.Persistence.DbContext;
using NvkInWay.Api.Persistence.Repositories;
using NvkInWay.Api.Persistence.Repositories.Impl;
using NvkInWay.Api.Services;
using NvkInWay.Api.Services.Impl;
using NvkInWay.Api.Settings;
using NvkInWay.Api.Utils;
using NvkInWay.Api.Utils.Impl;
using NvkInWay.Api.V1;
using NvkInWay.MediatR;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Configuration.AddUserSecrets<Program>();

builder.Services.AddOptions<JwtSettings>()
    .Bind(builder.Configuration.GetSection("JwtSettings"))
    .ValidateOnStart();

builder.Services.AddOptions<EmailConfigurationOptions>()
    .Bind(builder.Configuration.GetSection("EmailConfiguration"))
    .ValidateOnStart();

builder.Services.AddOptions<EmailVerificationOptions>()
    .Bind(builder.Configuration.GetSection("EmailVerification"))
    .ValidateOnStart();

var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
var key = Encoding.ASCII.GetBytes(jwtSettings!.Secret);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
                
                if (!string.IsNullOrEmpty(accessToken))
                {
                    context.Token = accessToken;
                }
                
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var claims = context.Principal!.Claims;
                var deviceId = context.Principal.FindFirst("device_id")?.Value;
                var jti = context.Principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                
                ArgumentException.ThrowIfNullOrEmpty(deviceId);
                ArgumentException.ThrowIfNullOrEmpty(jti);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("EmailVerified", policy 
        => policy.Requirements.Add(new EmailVerifiedRequirement()));
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddMediatRFromAssembly(typeof(Program).Assembly);

// Services
builder.Services.AddScoped<IPasswordHasher, Pbkdf2PasswordHasher>();

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IUserSessionRepository, UserSessionRepository>();
builder.Services.AddScoped<IUserVerificationRepository, UserVerificationRepository>();
builder.Services.AddScoped<IEmailSender, EmailSender>();
builder.Services.AddDbContext<ApplicationContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("AuthDatabase"));
});
builder.Services.AddAutoMapper(cfg => cfg
    .AddProfiles([new MappingProfile(), new DtoMappingProfile()]));

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "NvkInWay API",
        Version = "v1",
        Description = "API for NvkInWay application"
    });
    
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Введите JWT токен в формате: Bearer {token}"
    });
    
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            }, new List<string>()
        }
    });
    
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        options.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();