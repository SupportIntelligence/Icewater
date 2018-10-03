
rule k2318_3718bce1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3718bce1c2000b12"
     cluster="k2318.3718bce1c2000b12"
     cluster_size="171"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['5757859bb6ad5633ebf2cc08706ab8c8bb6a20b1','9baa10c4160115a4b319702624a70d4a40df0af4','5fd5ceb485b34c27c86ff7e4569141f496edd289']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3718bce1c2000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
