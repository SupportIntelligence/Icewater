
rule i2321_035bb6c9ec000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.035bb6c9ec000b12"
     cluster="i2321.035bb6c9ec000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['51890bb5f6fa27005487ea7b9dd6c56b','5d0780a1fae9cdd9f08bd51b4d3fe156','e44950cd7f0d52667569578b48c460ca']"

   strings:
      $hex_string = { f917cbb523b5dafc4c78766b6da1d9a855eab1e4ed4ec9b146a512c23772cf549a47e7cf9d2bd76747e7ea9552383e3cfeecf0e881a7b28ec381aeaf2e9c6fcc }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
