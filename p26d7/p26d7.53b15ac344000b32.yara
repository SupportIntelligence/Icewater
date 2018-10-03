
rule p26d7_53b15ac344000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d7.53b15ac344000b32"
     cluster="p26d7.53b15ac344000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installmonster symmi installmonstr"
     md5_hashes="['fdbbdf03a9893b726e2158298a405e67fb4afbcf','94e4b53a0d1f4808325ec4e5cba78e08dc075b4d','d982b3f79f197cba42c3fc50518de0a92578b626']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d7.53b15ac344000b32"

   strings:
      $hex_string = { 85237803f8ed7d638d557b4dda023a7cfa070f879324d14ce8e088900a4947ca6decd60d8b26214501dbe436c213080ceb441a04dc06bf20c91b76efde5dbc2f }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
