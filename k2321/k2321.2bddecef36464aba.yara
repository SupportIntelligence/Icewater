
rule k2321_2bddecef36464aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2bddecef36464aba"
     cluster="k2321.2bddecef36464aba"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['048d7747632d8cece4dd53880e863484','105c2fdd3a59b964d6e193a26cf3a3de','f60e3d8af82ff62332d282e21c4ed910']"

   strings:
      $hex_string = { b79e2c446aaede7dcac3b93b998a75b1004cbb33912b8b0ab5df0f19d029af14a9a4bec413c9ba7b2869ddc5e88d226e75fd3416e961a03578d2e3f7769cd630 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
