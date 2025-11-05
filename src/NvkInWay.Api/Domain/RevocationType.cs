namespace NvkInWay.Api.Domain;

public enum RevocationType : byte
{
    Logout,           // Пользователь вышел
    PasswordChange,   // Смена пароля
    AdminRevoked,     // Администратор отозвал
}