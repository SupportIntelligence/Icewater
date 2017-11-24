
rule i3ed_13925ea91dab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.13925ea91dab0912"
     cluster="i3ed.13925ea91dab0912"
     cluster_size="160"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor padodor symmi"
     md5_hashes="['00812ae3471c6394639fb5e518a69b7d','01a5acc5b39dd4213d99f1a47b9d973b','444cddc565fa9dad972fc0ac3aa79b88']"

   strings:
      $hex_string = { 7b088d0c768b348fe962ffffff31c0eb19558d6b106aff53e8a5feffff83c40c6a0be83f04000083c4045d5f5e5b89ec5dc35589e5535657837d0c017505e823 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
