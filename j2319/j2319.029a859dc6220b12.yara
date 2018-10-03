
rule j2319_029a859dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.029a859dc6220b12"
     cluster="j2319.029a859dc6220b12"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit blackhole"
     md5_hashes="['51070b8e5448d0881786647239b08c29dc655212','f92c73d770a4ace5ea3a1c70ea3d68527ad023b1','7bb5bff41779667d65350f789f96c93279383a96']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.029a859dc6220b12"

   strings:
      $hex_string = { 75c0a7a47b8ffe998c00962aff434b039527875af4b46747f669181505dbb0d82559b5909abaaca9ce65857a522378ac64fd553799df6cf9aeaad75246f31d45 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
