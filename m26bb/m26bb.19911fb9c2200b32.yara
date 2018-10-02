
rule m26bb_19911fb9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.19911fb9c2200b32"
     cluster="m26bb.19911fb9c2200b32"
     cluster_size="138"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pterodo autoruner attribute"
     md5_hashes="['43ea604c5ccff341741b371932cb79ee98385034','5ab0712007f3d7f522524d4159eb79bcc06b30a1','baa8414ff1f005796fc3bc12b11b3411ffc6b4e7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.19911fb9c2200b32"

   strings:
      $hex_string = { 67a8d756da8df477ba8e10763b613ae48cca0c07eb81471a4fd801d412bb6a31ae33a46c0dc8934ac59f1370188afcf69b59ac6e50ff0fe0b43f49aa9548ad85 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
