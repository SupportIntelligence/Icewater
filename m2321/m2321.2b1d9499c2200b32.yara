
rule m2321_2b1d9499c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1d9499c2200b32"
     cluster="m2321.2b1d9499c2200b32"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['036aa95a6e6fe23be0a89861a0ef4cdd','587eca5b3e6b7595a695f7a6540d3f1e','e8c0e51957a30d379a3d03aa75e167c1']"

   strings:
      $hex_string = { 0300cea74f3601e645b48297d6f583550df9e81b526aa621eac69518edb1d2b68012bc72687c4bf074470acd9863fa376e43cba3235d6f784206819f4490777f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
