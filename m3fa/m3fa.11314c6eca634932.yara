import "hash"

rule m3fa_11314c6eca634932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3fa.11314c6eca634932"
     cluster="m3fa.11314c6eca634932"
     cluster_size="2477 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="browsefox riskware adplugin"
     md5_hashes="['067ae9598c6a7834cfece75960ae38e3', '14b8f1df2d1be9710b8e80f529602467', '1308219a19fe93f84aea0e37729781e1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1024) == "1a008d58234fde63e1a48e6a7e3cf0df"
}

