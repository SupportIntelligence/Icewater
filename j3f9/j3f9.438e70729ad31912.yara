
rule j3f9_438e70729ad31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.438e70729ad31912"
     cluster="j3f9.438e70729ad31912"
     cluster_size="23"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['0be0662f4ef8880b8c8126599d74b7f8','177e57b2f42cf7ed60b0baee948bc718','a6a2368907ba29392116c223e28f7ad3']"

   strings:
      $hex_string = { 70356195b6b527fb0f6a5d640cb645f0d3c0f66d0b5202ee3c04264109430f80a240916decf6ed46060630a412462774d5d82d006cff760a50a15844420265db }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
