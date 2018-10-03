
rule m2319_412694982ab86bb6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.412694982ab86bb6"
     cluster="m2319.412694982ab86bb6"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['ff5ff98408876151e8fc902ee32c612db608a690','c14148a5c5c663d09bfac5e2cf6f69ca6e8ec57a','a16635df30526decc8a1fd4a1271ce62208dc723']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.412694982ab86bb6"

   strings:
      $hex_string = { 6e657248544d4c3d223c646976207374796c653d2777696474683a3470783b273e3c2f6469763e222c622e736872696e6b57726170426c6f636b733d712e6f66 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
