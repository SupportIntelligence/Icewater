
rule ofc8_691896a9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.691896a9c8800b16"
     cluster="ofc8.691896a9c8800b16"
     cluster_size="198"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['448fada2536b5f39e1337950279d53a0375bda28','c06c12f1d9f2c69199c32d3d4ece1c436b9ed088','301d29da8f37131d22914739e92fa0c7a3570077']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.691896a9c8800b16"

   strings:
      $hex_string = { b27cbebcef2956629f8cccfed238e35bd8823c3e018fab68a452114fce8ab5958d4ef49d23067291add441d7ee6ac03b43a2b18436a0c80f4560f337cb16ae93 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
