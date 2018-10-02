
rule k2319_691d06b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691d06b9caa00b32"
     cluster="k2319.691d06b9caa00b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6c95285829fea94ccb937bdb764dc1ede0052c86','46edac0aa2f7c7046ca37e4367c4ee14cd1dd949','da74d31f18b87ec22ef4a160bce6fd052f9e952d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691d06b9caa00b32"

   strings:
      $hex_string = { 362e3045312c36352e384531292929627265616b7d3b766172206c374439713d7b27483935273a342c27633171273a66756e6374696f6e284d2c4f297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
