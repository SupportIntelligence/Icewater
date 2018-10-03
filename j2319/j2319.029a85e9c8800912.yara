
rule j2319_029a85e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.029a85e9c8800912"
     cluster="j2319.029a85e9c8800912"
     cluster_size="146"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script exploit blackhole"
     md5_hashes="['d6a1e9e0719deb2448052115856e53e110e052b5','63158e89031b6415b990e331ebf86d94cffd5005','7ca80651b238d276982364400e553d487ba39ccb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.029a85e9c8800912"

   strings:
      $hex_string = { 6f7228693d303b693c7a2e6c656e6774683b692b2b297b7a612b3d537472696e675b66665d286528762b287a5b695d29292d3132293b7d7d3b7d3b70733d2273 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
