
rule j3f8_7094d6c3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7094d6c3c8000110"
     cluster="j3f8.7094d6c3c8000110"
     cluster_size="7"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['4d993b9c7cbafe44cf246ee4d96a1b51','653770b5c8ba8a6002237753f7d5d65d','d7c9d324a2eb43dfb094cca79ef8b81b']"

   strings:
      $hex_string = { 0001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d65000367 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
