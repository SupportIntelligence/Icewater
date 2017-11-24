
rule m3e9_13b95092427942d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b95092427942d2"
     cluster="m3e9.13b95092427942d2"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0cf463c2784297a198cfe9b8ae9a8b7b','665ff2cd69dd02844ff8d889883a950d','b6ece6af28e42fccc3082600768afb5d']"

   strings:
      $hex_string = { bbe8e441a37d7749c99016d139e33d2bb76e033ba45c50730555b84ad9be8783e54bfb6995236d98027e256f275d99deb1f8a097aeb294eb3cda6a099154d09d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
