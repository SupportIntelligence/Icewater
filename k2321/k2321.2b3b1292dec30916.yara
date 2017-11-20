
rule k2321_2b3b1292dec30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b3b1292dec30916"
     cluster="k2321.2b3b1292dec30916"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector moctezuma"
     md5_hashes="['16c560a12e2189bcb5e39bb8b8130272','518618d9d163da2dce558434579301ec','b21f77a8b0b053270726f671ba06f11f']"

   strings:
      $hex_string = { c4b0f567e4bd7a7801a1ee459b5ec8c547b3ab84487d95a3506fa7fb21ec923d7699bf2fd0499cba4651132c3e7c91262ef308f5fd02d7076c660559e3158ab4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
