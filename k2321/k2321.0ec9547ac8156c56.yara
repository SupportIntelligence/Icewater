
rule k2321_0ec9547ac8156c56
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ec9547ac8156c56"
     cluster="k2321.0ec9547ac8156c56"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yunsip zusy backdoor"
     md5_hashes="['2d2505504661e7a178c35ca164a96844','3f10e99609d5266981d214e834984fbf','f2d5813219ccef2ed23047907d35b57f']"

   strings:
      $hex_string = { 26bef36c01660f3c0bc0e1e6bcea8efd4af623e99aa9b175bb8c6e4bb6aea1fe69d38fcc2d8899361b7b8d541ae76fcdc12c81d75ada9f33d8646d62420a5ba7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
