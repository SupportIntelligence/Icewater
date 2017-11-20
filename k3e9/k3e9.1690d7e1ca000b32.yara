
rule k3e9_1690d7e1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1690d7e1ca000b32"
     cluster="k3e9.1690d7e1ca000b32"
     cluster_size="1350"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd bublik small"
     md5_hashes="['003821db664e5b5154b7c83cffb986f1','0048a722283c1db334693c50e2b0e4e6','0600f4b537e52866c20fa15d0d7fc489']"

   strings:
      $hex_string = { 5153e821ca74aa637986cec9c40066a9eea5e1b421eb5aa5284b69e32a882900d36fdc7168e7ee5c63106b1b25383c17fc6e95a07fa6712f20bdcbe076333454 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
