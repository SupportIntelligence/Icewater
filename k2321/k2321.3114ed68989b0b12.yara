
rule k2321_3114ed68989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.3114ed68989b0b12"
     cluster="k2321.3114ed68989b0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba vbkrypt zusy"
     md5_hashes="['8cd319b5d54a1c33fb055a20c6a0d8e2','97fcfba36f3ab7524b3ce7175f7f5010','cf2dddbe18887d259089ada598c1ea27']"

   strings:
      $hex_string = { 8be5d8d16360de07efbfd7cee7952c169785925d486225c21242b458a4944afcd52a4491607f1df6c40883d6a022bd064bc01ec4a7bc9cec575edc7ef0871f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
