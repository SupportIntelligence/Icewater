
rule i2321_045596c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.045596c9cc000b32"
     cluster="i2321.045596c9cc000b32"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['126b2c657f4cfe88490e3bcc00076cde','19bedf57a90950812f2d73b27035a183','4930d2e655bbaeee3a0e2fcc975149d6']"

   strings:
      $hex_string = { 06857442cd2669f5faae43ebcf9d3db3bc51befa7a7a76e2f03d6baf64ffb2de0a6179bd6df99db6a53fbf3ed42c7a7c5bac1037627f1a8fe917bf1ed373aba3 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
