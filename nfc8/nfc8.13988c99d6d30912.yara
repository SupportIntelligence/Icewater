
rule nfc8_13988c99d6d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.13988c99d6d30912"
     cluster="nfc8.13988c99d6d30912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gthyv ransom adlibrary"
     md5_hashes="['905e2e37f838cb554c938d25c773dfdb95a1a85b','baa204c70ba6c1c8ae99fa01dda65ae742942339','2db399c5134723093c65ad4f7b1a89f25801d29b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.13988c99d6d30912"

   strings:
      $hex_string = { d9615d8d9ced46c19a8939f7285167f610fd351d739d0e25b93e6c401c3b82ebd66b50c341f23352951996ab22bc1f2324153d8a69e6f9b8a47db686a3e80a78 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
