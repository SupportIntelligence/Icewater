
rule n26bb_419e9299c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.419e9299c6620b32"
     cluster="n26bb.419e9299c6620b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack awoyfwji patched"
     md5_hashes="['2e968e27521a36cbb748c78b906ac20bf090ac97','bdeb2b01049fe746d1f9adfae1898e80b7b655cf','0ffc219d0377c84f1a07c828d2a97107b9dec391']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.419e9299c6620b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
