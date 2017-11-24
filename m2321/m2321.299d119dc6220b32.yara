
rule m2321_299d119dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.299d119dc6220b32"
     cluster="m2321.299d119dc6220b32"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0f84230301292ee75271d50f5fe33597','18da11cfecdd3150617c22afb49684f9','d6bd6dcee9e44d86ef20650632b2222d']"

   strings:
      $hex_string = { cec8659d28cd9b9eb994e76758e9fa3943997ed52a3ae2085f8e67468bd2669aed76e6b637fe4fb30b90952003f45a191179e8da6c4581be264dd8628a8669ae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
