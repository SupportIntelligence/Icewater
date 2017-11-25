
rule k3f7_15d3795096c30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d3795096c30b32"
     cluster="k3f7.15d3795096c30b32"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['235c183552d0394543f898c4cbcca600','2b30050ec252e552da0032c7291bad2d','f7b77b64f902326ad766d10fb23bb1ee']"

   strings:
      $hex_string = { 343235373739333933313727292c6c3d782e6c656e6774683b7768696c65282b2b613c3d6c297b6d3d785b6c2d615d3b0d0a743d7a3d27273b0d0a666f722876 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
