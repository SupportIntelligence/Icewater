
rule m3e9_659485c8da9b6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.659485c8da9b6b16"
     cluster="m3e9.659485c8da9b6b16"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['14c95dc0e7403c11514edd75e2225c18','19e35e465af25c69c857ab585370df7a','c0577c0f3a7319f6cf189e379020eedc']"

   strings:
      $hex_string = { 8d4d805153ff90980800003bc6dbe27d0d6898080000575350e822a6fdff33c03975800f9ec033c9663975840f94c10bc175068b036a04eb138b450c66833801 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
