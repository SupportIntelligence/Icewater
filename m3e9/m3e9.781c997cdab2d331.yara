
rule m3e9_781c997cdab2d331
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.781c997cdab2d331"
     cluster="m3e9.781c997cdab2d331"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['04267189bbf4b661e9183806902c136e','22e1ea7dd8f895b5f80ea66c209cdf0b','d01ceac40564ffa102f48de7ed2225b3']"

   strings:
      $hex_string = { eb0bff3538364000e8a9eafdffd86dd0dfe0a80d0f8561030000e891edfdff8b4514d818dfe09e72056a0158eb0233c0f7d8f7db23c3668bd88d45e0508d45e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
