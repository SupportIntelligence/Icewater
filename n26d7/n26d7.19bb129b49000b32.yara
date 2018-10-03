
rule n26d7_19bb129b49000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.19bb129b49000b32"
     cluster="n26d7.19bb129b49000b32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="vittalia malicious downware"
     md5_hashes="['ce637910ce0d7ad5c8212fe725e635900bd8f2b9','4dab90ba9fdba194e1823b3c90eff9638cf74440','70541c9a825ac3585ed98be0393a6c43ef924d8d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.19bb129b49000b32"

   strings:
      $hex_string = { 8d48c94300c1e706c64439040085f6740c56e84694ffff5983c8ffeb0233c05f5e5dc3558bec8b45088b00813863736de0752583781003751f8b40143d200593 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
