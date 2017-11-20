
rule k2321_2914ad2dd89b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad2dd89b0912"
     cluster="k2321.2914ad2dd89b0912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['21e31690e97b6c8c82da0822693f6683','35f883ba4370e317b2410820e5380d12','eea97495936259b92eb6d4f321d613af']"

   strings:
      $hex_string = { fdb3b9a1e1fc850b9f7ff6d9cb2fbfbc71c386363eaf6431115f103cd47279a0560bca19745a7266063dc443e5f8d050a23b6d019e8cd207778b891e3a704041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
