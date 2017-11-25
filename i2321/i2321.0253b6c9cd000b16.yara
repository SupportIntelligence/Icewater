
rule i2321_0253b6c9cd000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.0253b6c9cd000b16"
     cluster="i2321.0253b6c9cd000b16"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['2a6738de3f718c014b06b37fa91cd15c','62cfbd55284a7c569c2fc4ddb3713e28','b1a0d7de0f3bc7a562e43702f3e2a143']"

   strings:
      $hex_string = { 6aa9104e8e8c3f3d327af089ace370b0fdab0b176b73d5fab942989c1819df8c57778c975e185b2cd52e4f152b8ba5914bb1e7621a7b26ceee64e9721a383a3c }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
