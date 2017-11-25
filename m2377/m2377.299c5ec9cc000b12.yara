
rule m2377_299c5ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.299c5ec9cc000b12"
     cluster="m2377.299c5ec9cc000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3bf4bd8fa9ddce7a1e8d6ade3c82ed6b','ce05dfe7c540e1c0794abd2fb601aec7','fa6a807de1da7ad1fc68d2d3a640944b']"

   strings:
      $hex_string = { 645cec5d15c1c5192f77485e9a5b2b2e0ed98fb03bf9586ce937acdc693ef20ad5b975bd45651b722551708e6bf82cfdf0adc7851ee260d04e30be437f38cb22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
