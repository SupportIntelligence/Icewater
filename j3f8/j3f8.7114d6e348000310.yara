
rule j3f8_7114d6e348000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7114d6e348000310"
     cluster="j3f8.7114d6e348000310"
     cluster_size="19"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['013640a9808e354597d45745ebeed6dc','17f06cb15ee59cec945210f441765f39','d568f01a57e031b7f750485c46384f75']"

   strings:
      $hex_string = { 2f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026616e64726f69642e6170702e416374697669 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
