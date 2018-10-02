
rule k2319_31363de9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.31363de9c8800932"
     cluster="k2319.31363de9c8800932"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['7ed142868cbedef4a82eb41f719c050381f1552e','53edc3809f7a6ffa38ef9a3d63b81c230eb72a83','a89675c5efd0e9ebf9499b684e7d7b80d723cfcc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.31363de9c8800932"

   strings:
      $hex_string = { 3139293a2831302e343345322c34352e292929627265616b7d3b7661722067364b343d7b275a3066273a66756e6374696f6e28482c47297b72657475726e2048 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
