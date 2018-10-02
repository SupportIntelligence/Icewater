
rule k2319_581343b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.581343b9ca800b12"
     cluster="k2319.581343b9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['160da46edf364905ce2efcb7af6507c0ef238708','bd97beef7462f5e1ec453d603d2ebd7680cc88d2','c25010df64afb2ff7541b607510a6aa91c65db3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.581343b9ca800b12"

   strings:
      $hex_string = { 3e307836443f2830783143432c313139293a2830783233422c39352e292929627265616b7d3b76617220583351383d7b27583164273a2274222c27433249273a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
