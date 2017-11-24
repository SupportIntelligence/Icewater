
rule k2321_0968b92599eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0968b92599eb1932"
     cluster="k2321.0968b92599eb1932"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['759dd08202c40811393f8e3a81a7c359','ab31f8030f801eeb7f3049fb880a6083','f51e520187652eba0fce0963eb42e672']"

   strings:
      $hex_string = { d183a482a5bd16558b60abcadb91c362b771241e4642fce7ed4388ffb0417ade6efa728af80fb3c73c330c905ed768ceb9e993b5aec91c3d1b322550de9b1103 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
