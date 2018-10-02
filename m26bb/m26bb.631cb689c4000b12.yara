
rule m26bb_631cb689c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.631cb689c4000b12"
     cluster="m26bb.631cb689c4000b12"
     cluster_size="327"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browserio generickd bgvp"
     md5_hashes="['95022ac8f4307753fb5248fedfb33211b465f97b','1546596dca55a664eca7df1ee564b733e0ce1ed4','7a0960f355f372549242279958e519898743676f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.631cb689c4000b12"

   strings:
      $hex_string = { d080e201f6da1bd281e22083b8edd1e833c24e75ea89048dc87d42004181f9000100007cd58b5424108b44240885d2f7d076238b4c240c570fb6398bf081e6ff }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
