
rule m3f7_431816c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.431816c9c8000912"
     cluster="m3f7.431816c9c8000912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['5645171e68511a7f6182fe9a9ddf7128','9f5a8c5d240d2317693a3611bcef8b77','d48e5d08d9def6d62adf0fc0720dd323']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d7961686f6f223e0a3c696d67207372633d22687474703a2f2f7777772e666565 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
