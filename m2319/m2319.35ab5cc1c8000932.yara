
rule m2319_35ab5cc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.35ab5cc1c8000932"
     cluster="m2319.35ab5cc1c8000932"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['12994647991d62fa726fbd07e224449713600968','7920b3a475d79255a42a52dc8a6dc57ab2669148','0f60067fa8b8abc630e68b8455dc0d7e082213b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.35ab5cc1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
