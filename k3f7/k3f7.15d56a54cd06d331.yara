
rule k3f7_15d56a54cd06d331
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d56a54cd06d331"
     cluster="k3f7.15d56a54cd06d331"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0503c8b0079328544539d1bc250d1481','41529ad870de10b1bd6362f4f729e8bb','70672e0035436bf5e9d7e27467df9568']"

   strings:
      $hex_string = { 292e7374796c652e646973706c6179203d20276e6f6e65273b7d3c2f7363726970743e0d0a093c2f626f64793e0a3c2f68746d6c3e0d0a3c212d2d2050657266 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
