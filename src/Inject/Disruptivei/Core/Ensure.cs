namespace Disruptive.Core
{
    using System;

    public static class Ensure
    {
        public static T NotNull<T>(T value, string paramName) where T : class
        {
            return value ?? throw new ArgumentNullException(paramName);
        }
        public static string NotNullOrEmpty(string value, string paramName)
        {
            return !string.IsNullOrEmpty(value) ? value : throw new ArgumentException("Value cannot be null or empty.", paramName);
        }
        public static string NotNullOrWhiteSpace(string value, string paramName)
        {
            return !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException("Value cannot be null, empty, or whitespace.", paramName);
        }
    }
}

