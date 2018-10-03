
rule j2319_029a850fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.029a850fc6220b12"
     cluster="j2319.029a850fc6220b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit blackhole"
     md5_hashes="['f90d8b9e254bf0d069cb93b544b05a9bd0ffee79','110ef9e3a5a8950b9641708c4c7917c481a8398d','379529a4760f8f3728210544b7d7e55c57232683']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.029a850fc6220b12"

   strings:
      $hex_string = { 75c0a7a47b8ffe998c00962aff434b039527875af4b46747f669181505dbb0d82559b5909abaaca9ce65857a522378ac64fd553799df6cf9aeaad75246f31d45 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
