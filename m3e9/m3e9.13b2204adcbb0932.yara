
rule m3e9_13b2204adcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b2204adcbb0932"
     cluster="m3e9.13b2204adcbb0932"
     cluster_size="39"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob simda"
     md5_hashes="['02e4cc6bb40b11de9722a78e779ae67b','053aa99254aa3c5ee4f83ee669fb0c56','8712e4479fb13fb72a364e3466bd1320']"

   strings:
      $hex_string = { 258b9967beb1492e9e656baa94e72fbc8c21c5f3bdcab25197cb6c31af4bfdedebd0c3f880199bc4c6adba85306690878e00898ddb4bc829f056fa082d266fc1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
