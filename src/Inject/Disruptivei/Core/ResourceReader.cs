namespace Disruptive.Core
{
    using System.IO;
    using System.Reflection;
    using System.Xml;

    public static class ResourceReader
    {
        public static Stream GetResourceStream(string name)
        {
            Ensure.NotNullOrEmpty(name, "name");
            return GetResourceStream(name, Assembly.GetCallingAssembly());
        }
        public static Stream GetResourceStream(string name, Assembly assembly)
        {
            Ensure.NotNullOrEmpty(name, "name");
            Ensure.NotNull(assembly, "assembly");
            return assembly.GetManifestResourceStream(name);
        }
        public static string GetResourceString(string name)
        {
            Ensure.NotNullOrEmpty(name, "name");
            return GetResourceString(name, Assembly.GetCallingAssembly());
        }
        public static string GetResourceString(string name, Assembly assembly)
        {
            Ensure.NotNullOrEmpty(name, "name");
            Ensure.NotNull(assembly, "assembly");
            using (StreamReader reader = new StreamReader(GetResourceStream(name, assembly)))
            {
                return reader.ReadToEnd();
            }
        }
        public static XmlDocument GetXmlDocument(string name)
        {
            Ensure.NotNullOrEmpty(name, "name");
            return GetXmlDocument(name, Assembly.GetCallingAssembly());
        }
        public static XmlDocument GetXmlDocument(string name, Assembly assembly)
        {
            Ensure.NotNullOrEmpty(name, "name");
            Ensure.NotNull(assembly, "assembly");
            XmlDocument document = new XmlDocument();
            document.LoadXml(GetResourceString(name, assembly));
            return document;
        }
    }
}

