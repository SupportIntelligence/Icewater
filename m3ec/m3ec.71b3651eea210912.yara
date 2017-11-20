
rule m3ec_71b3651eea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.71b3651eea210912"
     cluster="m3ec.71b3651eea210912"
     cluster_size="41"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool kmsauto kmsactivator"
     md5_hashes="['08907f8a14738e22882157dcb7a30860','0933fc2eb68584f67c5b1ce7d5868d43','49ba5a07c786a7f105408863070b8c42']"

   strings:
      $hex_string = { 204faeabb3d9431e97413113ee8cd955958339b9f064e3f4a49878e14e0dbc797ad2d829f1c2ed1060469d510366bb8d886d00ec85803e365e4c8ba05f09e8c9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
