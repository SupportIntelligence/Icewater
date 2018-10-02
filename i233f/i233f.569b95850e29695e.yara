
rule i233f_569b95850e29695e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i233f.569b95850e29695e"
     cluster="i233f.569b95850e29695e"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="voiv script expkit"
     md5_hashes="['71a29ef1df1b1b03bf5242b3ffdcff850d606762','1ad878d8090d14d187ece66632187c099133c3ed','1d0e72e745d787cd1e2a970e22408372f60b97cf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i233f.569b95850e29695e"

   strings:
      $hex_string = { 002e0030002200200065006e0063006f00640069006e0067003d0022005500540046002d003100360022003f003e000d000a003c005400610073006b00200076 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
