
rule k2321_2195eccd36664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2195eccd36664aba"
     cluster="k2321.2195eccd36664aba"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['00cde54215f56b3975cb4ab84ec5ddf9','1141c87a2d7e74123bed3b35bff01048','919683257049fb44a1d6a431682cc4f9']"

   strings:
      $hex_string = { b79e2c446aaede7dcac3b93b998a75b1004cbb33912b8b0ab5df0f19d029af14a9a4bec413c9ba7b2869ddc5e88d226e75fd3416e961a03578d2e3f7769cd630 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
