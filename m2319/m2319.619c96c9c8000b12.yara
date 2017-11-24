
rule m2319_619c96c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.619c96c9c8000b12"
     cluster="m2319.619c96c9c8000b12"
     cluster_size="25"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['08147e2a48c4777e82daf92826fecc36','0d3f8508b983f3b379422388fe69f384','72ef05c2c93ef761d0f79448577ea6d7']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d7961686f6f223e0a3c696d67207372633d22687474703a2f2f7777772e666565 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
