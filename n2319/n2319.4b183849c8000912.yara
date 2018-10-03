
rule n2319_4b183849c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b183849c8000912"
     cluster="n2319.4b183849c8000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['7eb2176e7dc996b2d736dde95697c5d9978d4c01','3d2e2169e58c4fb6b0554dd2345154e00bec1c5a','e1282d8df104940c736bb1bcd8bf517d2e64947b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b183849c8000912"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
