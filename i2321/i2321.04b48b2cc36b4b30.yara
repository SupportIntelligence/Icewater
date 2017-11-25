
rule i2321_04b48b2cc36b4b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.04b48b2cc36b4b30"
     cluster="i2321.04b48b2cc36b4b30"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['021a72a3b6244161a4f0e3c042a17b0c','0323a3ce5a0853cbc10c502d7a0da576','f87368e55c987237b99fee9f29c21f09']"

   strings:
      $hex_string = { af3f4ab29a2ca22ddfb97afcaeb9397efde68bf7e49fe2de75c6ff088f5c5276ddadf3ff33fd723c5b1f36f7f60da65da3e5eec1913dc3a5071e1f2af5a7c9b1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
