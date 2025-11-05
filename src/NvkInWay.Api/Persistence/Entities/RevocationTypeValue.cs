namespace NvkInWay.Api.Persistence.Entities;

public enum RevocationTypeValue : byte
{
    Logout,           // Пользователь вышел
    SecurityBreach,   // Подозрительная активность
    PasswordChange,   // Смена пароля
    AdminRevoked,     // Администратор отозвал
}