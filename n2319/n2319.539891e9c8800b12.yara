
rule n2319_539891e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.539891e9c8800b12"
     cluster="n2319.539891e9c8800b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clickjack"
     md5_hashes="['b8494f3a1571f11c31c0b9d3fb7d84c9f2d72039','774e14c8ef3b831aca8039d60bf29c6001241c2d','c48064677a309e9d572a9f126453a901fc22f65b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.539891e9c8800b12"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
