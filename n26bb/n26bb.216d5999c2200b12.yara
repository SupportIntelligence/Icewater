
rule n26bb_216d5999c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.216d5999c2200b12"
     cluster="n26bb.216d5999c2200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['7da117b2a7d90af7a16ef416147510516d61c9ea','e385d75c174bb27f769f1f7d356d4a408fd99eaa','38610b77d9b9d7c24c7fe478e2f36357c4b5bb80']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.216d5999c2200b12"

   strings:
      $hex_string = { 3bc5f72eddb4548b3c75794d9ab59d466b585d57282453c79c5960042133befaf265f3de2c30b3ee34a822c99339e5696eedff78989f001ca3f0f8d01b8c202b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
