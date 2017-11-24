
rule m2319_2b914116dd02fb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b914116dd02fb16"
     cluster="m2319.2b914116dd02fb16"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['092228f9100a91a397d1084c88c76a6d','561deb761db34a3f8483b49216736908','e86cb0fff85348f08b1790019aeae1dd']"

   strings:
      $hex_string = { 5761792532306f662532304c696665212d524f5341532e6a7067272077696474683d273732272f3e0a3c2f613e0a3c2f6469763e0a3c64697620636c6173733d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
