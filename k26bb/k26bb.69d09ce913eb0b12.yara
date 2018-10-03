
rule k26bb_69d09ce913eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.69d09ce913eb0b12"
     cluster="k26bb.69d09ce913eb0b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark malicious"
     md5_hashes="['794c757c3f6c851e479d6e8aff2744b17a72d622','cd35e5ce159c77a6e009e2878b463729c875e86f','8ea2d42bbb37aefa4e628886780b194334c98e49']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.69d09ce913eb0b12"

   strings:
      $hex_string = { d080e201f6da1bd281e22083b8edd1e833c24e75ea89048d981843004181f9000100007cd58b5424108b44240885d2f7d076238b4c240c570fb6398bf081e6ff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
