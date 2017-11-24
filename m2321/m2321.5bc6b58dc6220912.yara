
rule m2321_5bc6b58dc6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5bc6b58dc6220912"
     cluster="m2321.5bc6b58dc6220912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys zbot backdoor"
     md5_hashes="['16e7af6f9d7a0b45867fab4d80ee48da','518ea1d31ba11cb72007687ce193b9cd','e967ceaa4529ee4e13829f19ff49439d']"

   strings:
      $hex_string = { d5a5dce5edcd58d70676c4006cafabbb3e1360fb011c55c6b7ff6a0ee0f45180072eea4053a6defcd2025eca289b1e8e17cbaec1b697a4c9ac583094bd4d9ae8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
