
rule n2319_19125c8bc76f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.19125c8bc76f4912"
     cluster="n2319.19125c8bc76f4912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer bitcoinminer"
     md5_hashes="['040a86dffe4b28a98f9ea3eb4043e5cee577a1bf','35a207af59e4a75306df4cb5ca79445b00548a6b','53b55999c0546907d3ae38b312d4aee5224978bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.19125c8bc76f4912"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
