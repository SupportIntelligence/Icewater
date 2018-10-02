
rule k2319_1a1314b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1314b9c8800912"
     cluster="k2319.1a1314b9c8800912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b49ad21d0231b8a02d017d3085e32c0b2aea028b','25285ecef0df980151981de39cdeb095cdd46fd5','9212dc46e9652566793920b1c6ad412640b2360e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1314b9c8800912"

   strings:
      $hex_string = { 3f2836332c313139293a2832332e2c3078323045292929627265616b7d3b7661722061394239673d7b2779306d273a2244222c27423267273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
