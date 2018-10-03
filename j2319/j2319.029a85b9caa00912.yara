
rule j2319_029a85b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.029a85b9caa00912"
     cluster="j2319.029a85b9caa00912"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit blackhole"
     md5_hashes="['ee08cc9bd5c66a0d9937e6f3de1821a070667334','df113a0002174c6d8536a85510c59f561e18bbd2','7bcb46ac69b820aa1b1cb0b525314873e4ca9a4e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.029a85b9caa00912"

   strings:
      $hex_string = { 75c0a7a47b8ffe998c00962aff434b039527875af4b46747f669181505dbb0d82559b5909abaaca9ce65857a522378ac64fd553799df6cf9aeaad75246f31d45 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
