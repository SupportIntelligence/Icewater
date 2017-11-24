
rule m2321_13b2204adcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.13b2204adcbb0932"
     cluster="m2321.13b2204adcbb0932"
     cluster_size="119"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['00b8506920a1995b6215f44ed36a6cf7','00f82f26f5fd170f650452e0e15b930d','1aeb6ded8c2a817aaadcb180a9aa2bda']"

   strings:
      $hex_string = { 258b9967beb1492e9e656baa94e72fbc8c21c5f3bdcab25197cb6c31af4bfdedebd0c3f880199bc4c6adba85306690878e00898ddb4bc829f056fa082d266fc1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
