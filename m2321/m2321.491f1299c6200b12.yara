
rule m2321_491f1299c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491f1299c6200b12"
     cluster="m2321.491f1299c6200b12"
     cluster_size="27"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys graftor kryptik"
     md5_hashes="['0dfe06077b1f828eabfa8bbb58100404','125feb1123006d05a452964dd9c3784d','b821af130b47b6aaf41abdf49c3513ad']"

   strings:
      $hex_string = { 03fbe5c0dfce22fe08670a2e4277fa8d4d6f94a88e837336cd7851d84a186d8fbbe85f0da65275b76aba33c212d5252a89e6e95dbcb7a15780ea1390415640d3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
