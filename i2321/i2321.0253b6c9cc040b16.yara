
rule i2321_0253b6c9cc040b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.0253b6c9cc040b16"
     cluster="i2321.0253b6c9cc040b16"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['26952bdf0183117ff5914987d566b685','2b2d24de4aff68b4e0e1f410aad719db','d57c6f1d27440292b2eb451240e76eba']"

   strings:
      $hex_string = { 6aa9104e8e8c3f3d327af089ace370b0fdab0b176b73d5fab942989c1819df8c57778c975e185b2cd52e4f152b8ba5914bb1e7621a7b26ceee64e9721a383a3c }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
