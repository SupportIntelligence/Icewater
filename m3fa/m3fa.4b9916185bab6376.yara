import "hash"

rule m3fa_4b9916185bab6376
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3fa.4b9916185bab6376"
     cluster="m3fa.4b9916185bab6376"
     cluster_size="2444 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="browsefox riskware uvpa"
     md5_hashes="['09fa32c44bba51494c332416ccc02e90', '127d4ce416af3f49853bd9f28eef7cc4', '0ab40a8d348721b05464a5d727f660c9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(247296,1024) == "4c34b858dd4e6f3117d2d502319e625c"
}

