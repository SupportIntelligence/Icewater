
rule j2321_1916168eee650932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.1916168eee650932"
     cluster="j2321.1916168eee650932"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cdvq ageneric backdoor"
     md5_hashes="['1da38fa93004defad6ab83243e33f67b','22fc193f8cafa272f5286ed2b125e871','d6b18970acdfc9a87f095479cb583d0a']"

   strings:
      $hex_string = { 6f5fa21fc5309b377438432268ed0f3c87d300fa0e2406511cac031bc290a1b44602cfe0348cbe51c4708a236cde822319328ad6d1402a9cc6d0772c318ee278 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
