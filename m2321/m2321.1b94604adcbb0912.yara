
rule m2321_1b94604adcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1b94604adcbb0912"
     cluster="m2321.1b94604adcbb0912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['9ba3e1a86680b9643230d5b85b4d8aa8','bff1fe8208d69c4a8c5fe17cf0a6849a','f7021c9df39cebf62b1e8d4f47aab176']"

   strings:
      $hex_string = { 258b9967beb1492e9e656baa94e72fbc8c21c5f3bdcab25197cb6c31af4bfdedebd0c3f880199bc4c6adba85306690878e00898ddb4bc829f056fa082d266fc1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
