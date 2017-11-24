
rule m3e9_131b90b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.131b90b9c8800b12"
     cluster="m3e9.131b90b9c8800b12"
     cluster_size="37"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz xixlpbc"
     md5_hashes="['1de007df4bffa9888578a9c1a221c7ba','1e6b48ed1b1e6fdcf7130a6b66f843bd','7c9be4018a077e1b7ae1d8c09b7d9280']"

   strings:
      $hex_string = { 767032377e73feda6c714cbc59752127e3b3eceda1bbd4cb92efb8fb41f935bed2bd9eaf5fee61b58c241c4654bf44ab7d4d57e41321dcb2f6c90507fadf1b77 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
