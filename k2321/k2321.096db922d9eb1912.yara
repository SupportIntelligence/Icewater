
rule k2321_096db922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.096db922d9eb1912"
     cluster="k2321.096db922d9eb1912"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['50554932ecdfc56667d5ba1784d1a2ba','9caebabca7e6a0ed451907ed2cd34449','ceb6b580c390c50952183a28851b24b5']"

   strings:
      $hex_string = { aa4d3e465a18174a67e6a5a6d6a23d29e681ef3b02a460530ff1693cfa14bb1cc34b83a498baf2106dc8e27c1d2bda908d850bf69499f91bb08f162754950c9a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
