
rule m3f7_03b555e2ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.03b555e2ca210912"
     cluster="m3f7.03b555e2ca210912"
     cluster_size="57"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['0f1b362dce148ee2ef4b2eb3521b8d8e','13a03080c1f251ca977fb76a35378f03','5a7fb06e781f275699456f67bebf0044']"

   strings:
      $hex_string = { 696768743a20313370783b2077696474683a20313570783b223e3c2f6469763e2d2d3e0a3c696672616d6520616c6c6f775472616e73706172656e63793d2774 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
