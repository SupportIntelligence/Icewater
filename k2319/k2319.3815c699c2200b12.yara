
rule k2319_3815c699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3815c699c2200b12"
     cluster="k2319.3815c699c2200b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['e0479ae299151c4057065149fdf9e97e17156558','f73a0e59e5d488eedd465d7ed2bc409e82ad9cab','3bb71a00269e77c4aaf824e125cb1e2b852c3954']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3815c699c2200b12"

   strings:
      $hex_string = { 2830783233362c37392e38304531292929627265616b7d3b76617220693456334d3d7b2769327a273a226368222c2773324d273a66756e6374696f6e28422c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
