
rule i445_0b21dc8986201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b21dc8986201122"
     cluster="i445.0b21dc8986201122"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot darkbot winlnk"
     md5_hashes="['4c1b18163b4d2aba61e865d8f125981a','a2cee258acb3813553862d85ac8c23e9','d0e01a3f2e98570f5efdbbb9628180ae']"

   strings:
      $hex_string = { 000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
