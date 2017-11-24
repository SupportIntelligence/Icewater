
rule n2321_39b0969cdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.39b0969cdee30912"
     cluster="n2321.39b0969cdee30912"
     cluster_size="32"
     filetype = "zlib compressed data (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundloreca bundlore bnodlero"
     md5_hashes="['01c43985558017502b49f2d2c3fd8301','2075b3ecb87fe4adcdb6575ed171137a','779475cc1f69e57f32e5f5e181317aed']"

   strings:
      $hex_string = { 99c39197419b0ce23e3d289d575eadd1966cccce8505b7a6c00f89278ba18aac0902163fd04b285806b9491e7390238810820de69e22e44d33bcde15261b54cd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
