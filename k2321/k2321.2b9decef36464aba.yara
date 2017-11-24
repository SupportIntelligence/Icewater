
rule k2321_2b9decef36464aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b9decef36464aba"
     cluster="k2321.2b9decef36464aba"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['1db791dcb835bca6cef737bf5dc2113e','4ae6c1c8658066dd921c10ab4197b103','b55446e57e85eea130f737f9f82873e0']"

   strings:
      $hex_string = { b79e2c446aaede7dcac3b93b998a75b1004cbb33912b8b0ab5df0f19d029af14a9a4bec413c9ba7b2869ddc5e88d226e75fd3416e961a03578d2e3f7769cd630 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
