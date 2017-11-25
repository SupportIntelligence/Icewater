
rule k2321_09617922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09617922d9eb1912"
     cluster="k2321.09617922d9eb1912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['0a405c12fe590a0b44ce68ad464c88c6','2d25a5a811b748a7dd45d1b8c6cda861','dbc8beb3b21d4b7ab5d56deeb6299824']"

   strings:
      $hex_string = { 1441da2fcb5fc5b06cef31e750b77be42b607d9dd9898e169a40e576f92e064eaf3e660f7e7bf20794341001512849b5865469f5a54e2658211e7a3c26d17f47 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
