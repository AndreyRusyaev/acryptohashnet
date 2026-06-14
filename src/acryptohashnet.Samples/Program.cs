using System.Diagnostics;
using acryptohashnet;

using static System.Console;

WriteLine();

var loremIpsumMsg = "Lorem ipsum is placeholder text commonly used in the graphic, " +
                    "print, and publishing industries for previewing layouts and visual mockups.";

WriteLine($"Message:   '{loremIpsumMsg}'");
WriteLine($"MD5:       {HashDataTool.Md5(loremIpsumMsg)}");
WriteLine($"SHA1:      {HashDataTool.Sha1(loremIpsumMsg)}");
WriteLine($"Sha2_256:  {HashDataTool.Sha2_256(loremIpsumMsg)}");
WriteLine($"Sha2_512:  {HashDataTool.Sha2_512(loremIpsumMsg)}");
WriteLine($"Sha3_256:  {HashDataTool.Sha3_256(loremIpsumMsg)}");
WriteLine($"Sha3_512:  {HashDataTool.Sha3_512(loremIpsumMsg)}");
WriteLine($"Keccak256: {HashDataTool.Keccak256(loremIpsumMsg)}");
WriteLine($"Keccak512: {HashDataTool.Keccak512(loremIpsumMsg)}");

WriteLine();

var filePath = @"C:\Windows\explorer.exe";

WriteLine($"File:      {filePath}, size: {new FileInfo(filePath).Length} bytes, version: {FileVersionInfo.GetVersionInfo(filePath).FileVersion}.");

WriteLine($"MD5:       {HashFileTool.Md5(filePath)}");
WriteLine($"SHA1:      {HashFileTool.Sha1(filePath)}");
WriteLine($"SHA256:    {HashFileTool.Sha2_256(filePath)}");
WriteLine($"SHA512:    {HashFileTool.Sha2_512(filePath)}");
WriteLine($"SHA3-256:  {HashFileTool.Sha3_256(filePath)}");
WriteLine($"SHA3-512:  {HashFileTool.Sha3_512(filePath)}");
WriteLine($"Keccak256: {HashFileTool.Keccak256(filePath)}");
WriteLine($"Keccak512: {HashFileTool.Keccak512(filePath)}");


