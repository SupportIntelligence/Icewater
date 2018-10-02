
rule k2319_791a94b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.791a94b9c8800b32"
     cluster="k2319.791a94b9c8800b32"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9794f5f3898b5a6201ae04f54cccea3d436a2aca','7486d4bd9cce643f4729e875c9300bfdfe6ca1b5','756fe3ff0f05f434f6a431b31145f924243a526c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.791a94b9c8800b32"

   strings:
      $hex_string = { 3139293a2836322c32302e354531292929627265616b7d3b766172204a3143367a3d7b27743469273a227868222c274c387a273a66756e6374696f6e28512c42 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
