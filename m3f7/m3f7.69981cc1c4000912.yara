
rule m3f7_69981cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.69981cc1c4000912"
     cluster="m3f7.69981cc1c4000912"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['0bdd0dd96cd6ac06f68defd8ee3d218a','0e249fc38517792f67e3b3386b7a7461','d545a59719ed8c97de9f68b10178aa8d']"

   strings:
      $hex_string = { 63726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
