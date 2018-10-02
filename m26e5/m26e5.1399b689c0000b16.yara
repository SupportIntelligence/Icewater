
rule m26e5_1399b689c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26e5.1399b689c0000b16"
     cluster="m26e5.1399b689c0000b16"
     cluster_size="71"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious zusy pemalform"
     md5_hashes="['d2502f7a472ef63daba30c142d0910043a989ce8','20cdf208ee5779f284bb6ae9f72618dfbbf9c54e','546d7660036c49cc56003a208490e0027faca8a6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26e5.1399b689c0000b16"

   strings:
      $hex_string = { 65a1b40e4199c0142a6aa7c1255d84d1ed2e75a9cd025add80ec207cb8e01d5e76a2e7324299e82a2d63b0f2135ea8e8f73f57b1c51e47d3a0ec203396c80452 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
