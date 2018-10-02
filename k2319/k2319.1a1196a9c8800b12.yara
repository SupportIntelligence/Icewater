
rule k2319_1a1196a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1196a9c8800b12"
     cluster="k2319.1a1196a9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4868b8b33ad6390a06906e6727796b4d50fb42db','adaef2d75eac716ff4d5162b1fb2bc506b493db8','a6d4126076ce02119cada38f94bc77ac9d1afdae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1196a9c8800b12"

   strings:
      $hex_string = { 5b565d213d3d756e646566696e6564297b72657475726e204f5b565d3b7d766172207a3d28392e3545323e28312e3031373045332c37362e354531293f283634 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
