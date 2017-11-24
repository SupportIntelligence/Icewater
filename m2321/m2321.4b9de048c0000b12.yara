
rule m2321_4b9de048c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b9de048c0000b12"
     cluster="m2321.4b9de048c0000b12"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yunsip zusy backdoor"
     md5_hashes="['06892647db58d7a8d117b4faf20e775a','23609e67772f0f111416727f0540a7d8','cf0ae08f08828e94d9f930de805643cb']"

   strings:
      $hex_string = { 26bef36c01660f3c0bc0e1e6bcea8efd4af623e99aa9b175bb8c6e4bb6aea1fe69d38fcc2d8899361b7b8d541ae76fcdc12c81d75ada9f33d8646d62420a5ba7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
