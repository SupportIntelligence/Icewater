
rule i3ed_07bb33e3222c9116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e3222c9116"
     cluster="i3ed.07bb33e3222c9116"
     cluster_size="1005"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue bundpil accv"
     md5_hashes="['002645fdf29aa9cee73a215b7d7a74a2','00321a6c54edf841d06025d20d9fbaa9','05a7c55c167259f4a0b78a7d440feae5']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a13832001083ee04ebea50ff151c20001083253832001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
