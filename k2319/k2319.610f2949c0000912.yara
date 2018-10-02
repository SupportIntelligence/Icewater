
rule k2319_610f2949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610f2949c0000912"
     cluster="k2319.610f2949c0000912"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['bf89d31a33c7a9fef340adf73c0a3f2d01ff548e','f4e80b6164ebb9ee9002ce7b0a99978f9e65a35a','121b013772c83a64ba7df7f53e4db69eaa1464ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610f2949c0000912"

   strings:
      $hex_string = { 623c5a3b7d7d3b2866756e6374696f6e28297b766172204f373d22686f222c493d22656e74222c55373d226164222c56373d28307842353c2838312e2c313339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
