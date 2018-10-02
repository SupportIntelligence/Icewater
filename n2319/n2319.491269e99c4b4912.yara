
rule n2319_491269e99c4b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.491269e99c4b4912"
     cluster="n2319.491269e99c4b4912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script classic"
     md5_hashes="['fdfdc6947b318764c6928b2818b487795ce089bd','b8a217485f51577aa52fe5b54c5bed9ddbc6b45b','fc26409113c42e0f100572c49fd3fa14ee5bce53']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.491269e99c4b4912"

   strings:
      $hex_string = { 3d22303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
