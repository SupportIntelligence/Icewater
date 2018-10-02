
rule k2318_23135fa9c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.23135fa9c2000b32"
     cluster="k2318.23135fa9c2000b32"
     cluster_size="95"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['0f8e1f10b8e86a1e97b11160cb5f2c91ec8cbab4','9cb25008da1e7274ba549cc5b3da424f1de66e63','7367bd42d24a4578564e4a6da9d34c2f33642cf7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.23135fa9c2000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
