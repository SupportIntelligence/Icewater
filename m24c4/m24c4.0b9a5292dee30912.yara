
rule m24c4_0b9a5292dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.0b9a5292dee30912"
     cluster="m24c4.0b9a5292dee30912"
     cluster_size="4"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['01335ae9050de9919574684836fb33a8','3c4b78daf964901a96edb81674463ce1','54beb5ee4f4761dbb991c92dbdbad032']"

   strings:
      $hex_string = { 1a718eb0d52678b44f2568e5333cc43ab138455e9a51e684855cd07bf4c23614e9018dd8cb8bdf66fe1c5337e2a73eca6b985f7fc564a84b025629e213afd430 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
