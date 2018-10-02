
rule n26bb_4654b56bc6fb9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4654b56bc6fb9b12"
     cluster="n26bb.4654b56bc6fb9b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious ajlxj"
     md5_hashes="['9685c184027695fe3919161d6d017a0a4cfca648','832287a38025aba77079687d4345b0698788fd28','e6a15ba072f5da93f9376c488435a618bb0b1adc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4654b56bc6fb9b12"

   strings:
      $hex_string = { 7ed8f10afefc8841bdeba7906471cbe3f4fa7c1b3f713c47bbcd6137425faeafaaa5e4196256c54fa0c01758028e105724c3dd6f034efe4bb1853d77768dc90c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
