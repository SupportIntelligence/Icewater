
rule m3f7_639d93c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.639d93c9c8000912"
     cluster="m3f7.639d93c9c8000912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack script"
     md5_hashes="['3c005ea57a37a0e5a3373a81f5399656','5a038844f8af294e7163f7dfef9e744c','ea7c659f6c91956e4f1d9bf3f4897abb']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d7961686f6f223e0a3c696d67207372633d22687474703a2f2f7777772e666565 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
