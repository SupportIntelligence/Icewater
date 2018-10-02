
rule n2319_489a5388cd0b9191
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.489a5388cd0b9191"
     cluster="n2319.489a5388cd0b9191"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['7e3a49c18ae4a8c16d034642d535ca174a1008a0','8300e5aa0adc29d0d435bd5b946401f3fffe4df4','56306e666961e1c4fca05469c750927e78f460e1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.489a5388cd0b9191"

   strings:
      $hex_string = { 643d7b747970653a21412626763f224e4f5f464c415348223a22494e49545f54494d454f5554227d3b696628427c7c6229632e757365466c617368426c6f636b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
