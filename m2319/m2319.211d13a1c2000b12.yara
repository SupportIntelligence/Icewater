
rule m2319_211d13a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.211d13a1c2000b12"
     cluster="m2319.211d13a1c2000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['0b0b4d51497c1d96b3448ffad741f2d5a27841fe','857fbbf16da285f82a47bf116e30caf7318f3260','d1075521d45b6a477f2b595d19884d69dbf1eae9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.211d13a1c2000b12"

   strings:
      $hex_string = { 772c646f63756d656e742c77696e646f772e5f7770656d6f6a6953657474696e6773293b0a09093c2f7363726970743e0a09093c7374796c6520747970653d22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
