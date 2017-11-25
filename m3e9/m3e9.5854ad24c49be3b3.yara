
rule m3e9_5854ad24c49be3b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5854ad24c49be3b3"
     cluster="m3e9.5854ad24c49be3b3"
     cluster_size="152"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['0784d7ca610f9d9e23084f88fcb9fef9','0f2bfe0889efa5924e4bcec20ee5a948','a4273f40fe96034464605891748d6436']"

   strings:
      $hex_string = { c699f7f98955a8dd4510e8274ffdff25ff7f00008985a8feffffdb85a8feffffdd5dbceb638b4518998bf033f22bf2dd05b03c4000833d00304300007508dc35 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
