
rule k2319_3912f662ca42b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3912f662ca42b912"
     cluster="k2319.3912f662ca42b912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['b68355a813bd42bb0e5ffdff8030d35dd8e99805','3129a14efbb3dc12c078c174b63bd114d2f93400','e0fb17ed87f024616850cfc8b16215d87fd1603f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3912f662ca42b912"

   strings:
      $hex_string = { 28392e32303045322c3078323436292929627265616b7d3b7661722043394939343d7b274d3754273a227274222c27533834273a66756e6374696f6e28592c48 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
