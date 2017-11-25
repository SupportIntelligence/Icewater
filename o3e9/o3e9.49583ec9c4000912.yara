
rule o3e9_49583ec9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49583ec9c4000912"
     cluster="o3e9.49583ec9c4000912"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock malicious nabucur"
     md5_hashes="['13034b0997c5e9ffce04eb9f2c3d874b','25a676959e895ac4a8e8872759d6c997','beca40d7310248835cc866571b88bfa5']"

   strings:
      $hex_string = { f8d5b4fff5d3b3fff3d0b2fff0ceb0ffeecbafffeccaadffebc8acffe8c6aaffe5c3a9ffe3c1a7ffe2c0a6ffe0bea4ffddbba3ffdab9a2ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
