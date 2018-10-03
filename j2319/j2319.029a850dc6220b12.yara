
rule j2319_029a850dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.029a850dc6220b12"
     cluster="j2319.029a850dc6220b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit blackhole"
     md5_hashes="['b1600ec1d86081b9d7b61a31745939528be26cf4','f58190022f78ef8e8008f304b4eb9cc87946f765','1a2f69254cf6349b716e25256f9a8c6fbb2da743']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.029a850dc6220b12"

   strings:
      $hex_string = { 75c0a7a47b8ffe998c00962aff434b039527875af4b46747f669181505dbb0d82559b5909abaaca9ce65857a522378ac64fd553799df6cf9aeaad75246f31d45 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
