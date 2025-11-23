using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace NvkInWay.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddedVerifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Verifications",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    UserId = table.Column<long>(type: "bigint", nullable: false),
                    UnconfirmedEmail = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    VerificationCodeCreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    VerificationCodeExpiredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UnconfirmedEmailCode = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    VerificationCode = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: true),
                    LastVerificationAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    NotActual = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Verifications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Verifications_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Verifications_UnconfirmedEmailCode_VerificationCodeExpiredAt",
                table: "Verifications",
                columns: new[] { "UnconfirmedEmailCode", "VerificationCodeExpiredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Verifications_UserId_VerificationCodeCreatedAt",
                table: "Verifications",
                columns: new[] { "UserId", "VerificationCodeCreatedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Verifications");
        }
    }
}
