
rule k3f7_15d36a54cd079b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d36a54cd079b32"
     cluster="k3f7.15d36a54cd079b32"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['013bcc10a4594f4b31ce1560e98a6019','2f5e3149cfddc8e290ab61822df7c652','fceacfd571a5f0b8200ce2ced0a268af']"

   strings:
      $hex_string = { 292e7374796c652e646973706c6179203d20276e6f6e65273b7d3c2f7363726970743e0d0a093c2f626f64793e0a3c2f68746d6c3e0d0a3c212d2d2050657266 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
