
rule m3f7_6319400ad7a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6319400ad7a30b12"
     cluster="m3f7.6319400ad7a30b12"
     cluster_size="24"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0a857e25f5e24e7ec93e5ff71a80921b','0b6d6913df6c1a38b66d61d5cc547a2b','9b1031b6412f655c48b2172421e6cdd6']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
