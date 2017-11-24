
rule k2321_13b294aad9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13b294aad9eb1912"
     cluster="k2321.13b294aad9eb1912"
     cluster_size="42"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['0985f17ddc5ecc93a368502f156dc785','12c8025fc3a0bd6ca5fb76fe96a499ca','8f22b92d89828926be18567d01319b29']"

   strings:
      $hex_string = { 47775d60ad16d442f4ae72b539ac9a32301b6e898b8506e72c9eb7e5a55a368710b21ae9dff8f013b65fcdbdb1ce8a0474322927f6e87c4512d540ff98d0b9e3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
