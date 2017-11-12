
rule m3e9_611455b8dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611455b8dee30912"
     cluster="m3e9.611455b8dee30912"
     cluster_size="121"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef autorun"
     md5_hashes="['01b3155bf87190877c3ef5a70d5a3694','021b9e67a190b811bb1b8d9497a528f5','5074a1c861bc3b24f5d70b4e67505b88']"

   strings:
      $hex_string = { c745fc1300000068940000006880200000e857bafeffe8e8b1feffc745fc14000000837dd4000f8447010000c745fc150000006a006a046a016a008d85f8f6ff }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
