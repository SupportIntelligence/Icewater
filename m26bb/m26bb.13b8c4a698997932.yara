
rule m26bb_13b8c4a698997932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13b8c4a698997932"
     cluster="m26bb.13b8c4a698997932"
     cluster_size="1069"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd ransom gandcrab"
     md5_hashes="['11c74d39bbe0926530929f8f769cf03763383a4e','63727cee27c9361b07bf71f486b85028bcc5ea53','87341122a4cd0a66d281cbcf84b79b1279d00dcb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13b8c4a698997932"

   strings:
      $hex_string = { 0b170a6836de51851ced3ebfa1e7b8280ff8ac199c4802f512808ebb5e1d3f4ac3714c5aa074aaab667324332c9f376d9ab589f638875601ad16451a3b582903 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
