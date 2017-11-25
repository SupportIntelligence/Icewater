
rule m3f7_6b983ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b983ac1c4000b12"
     cluster="m3f7.6b983ac1c4000b12"
     cluster_size="25"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['0473eaefd8617fd1e60afeff069bec96','0814f621b4c37ff427484d414567cf1c','b4213d182bedd43eb65ffcf87865542b']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d616f6c223e0a3c696d67207372633d22687474703a2f2f7777772e6665656461 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
