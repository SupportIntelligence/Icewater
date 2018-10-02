
rule k2319_120a96b9c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.120a96b9c2200912"
     cluster="k2319.120a96b9c2200912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4f5695b26f16c3b571408679bf8c2943b1031e8f','96bbbb328e968e749c617c3bcc47141452298851','85f8a632331152165887924287aa88b9a21b9a93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.120a96b9c2200912"

   strings:
      $hex_string = { 3f28312e30333645332c313139293a2839362e3545312c30783141292929627265616b7d3b76617220793559376c3d7b2751396c273a66756e6374696f6e286a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
