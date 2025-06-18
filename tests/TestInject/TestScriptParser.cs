using Disruptivei;
using Shouldly;
using Xunit;

namespace TestInject
{
    //
    // Test cases for the ScriptParser class
    // Should test the ability to detect PowerShell scripts from a command line string
    // C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass "C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1 -logFile C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1.log

    public class TestScriptParser
    {
        [Fact]
        public void CanDetectPowershellFromCommandLine()
        {
            //var cmdLine = @"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe"" -ExecutionPolicy Bypass ""C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1 -logFile C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1.log";

            var cmdLine = @"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe"" -ExecutionPolicy Bypass ""..\..\Scripts\iis.PS1 -logFile C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1.log";

            var parser = new ScriptParser();
            var result = parser.ProbeScript(cmdLine);
            result.match.ShouldBeTrue("The command line should be recognized as a PowerShell script.");

        }

    }
}
