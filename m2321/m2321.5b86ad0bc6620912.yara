
rule m2321_5b86ad0bc6620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b86ad0bc6620912"
     cluster="m2321.5b86ad0bc6620912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys zbot backdoor"
     md5_hashes="['0c837889b52a0790ea119e9bed7bad9b','16d082058e3d9fd1d8fe831c2d36d1cc','f7c98b7279256ec9bd47981121c0b393']"

   strings:
      $hex_string = { d5a5dce5edcd58d70676c4006cafabbb3e1360fb011c55c6b7ff6a0ee0f45180072eea4053a6defcd2025eca289b1e8e17cbaec1b697a4c9ac583094bd4d9ae8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
