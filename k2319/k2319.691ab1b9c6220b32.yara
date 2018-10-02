
rule k2319_691ab1b9c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691ab1b9c6220b32"
     cluster="k2319.691ab1b9c6220b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['113c84aa0c636d01abe2a491c94580d5069e1030','3ac8963ec7299eb862c35fa1352f50ca882d5feb','7b5aa87a62c8cb5e8081d4d6b3d23b68014e2d49']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691ab1b9c6220b32"

   strings:
      $hex_string = { 31332e313445322c30783735292929627265616b7d3b766172204e375936783d7b277a3067273a2866756e6374696f6e28297b766172204f3d66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
