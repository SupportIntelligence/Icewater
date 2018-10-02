
rule o26bb_3139cca9d9eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3139cca9d9eb0b12"
     cluster="o26bb.3139cca9d9eb0b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adload malicious"
     md5_hashes="['ccf2e3cd4bc2d71e8cee5fd166643257abf4642f','ed07a79f1a3e9d6e4d87901c6b6f68c6be2fc182','d0c81d0f0a98248c7023c425270ccc9e01a9dfe2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3139cca9d9eb0b12"

   strings:
      $hex_string = { 6f79456e7669726f6e6d656e74426c6f636b0055534552454e562e646c6c003f004765744164617074657273496e666f004950484c504150492e444c4c000005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
