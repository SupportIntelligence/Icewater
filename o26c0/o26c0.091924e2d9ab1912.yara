
rule o26c0_091924e2d9ab1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.091924e2d9ab1912"
     cluster="o26c0.091924e2d9ab1912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor kryptik gjjv"
     md5_hashes="['9c7255255a75ecfd39da323ae9c14f6c12d819f6','374051fec1b802cfce88d0e6cab4bb6142537df4','ca26f8ce0c23c948db1275c45d447743ec9abf2d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.091924e2d9ab1912"

   strings:
      $hex_string = { a9bf6c8d54939f4c3577e03e37585f8041059215fa652ac07f858bb779995b605a822fdff4637016893336d3e771de9a0039780f683509488457cd12100c0255 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
