
rule n2319_11e9693698af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11e9693698af4912"
     cluster="n2319.11e9693698af4912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner coinhive"
     md5_hashes="['0463e5c73ce7761922bb00d1078f07dfa32ae77d','4a2032650ac1011bfbe42d9ae0868fc186ba29ee','9a8b8ebc54cda28b3491db70144b2b922750b2b1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11e9693698af4912"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
