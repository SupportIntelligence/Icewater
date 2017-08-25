import "hash"

rule m3eb_1b141aadc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3eb.1b141aadc6200b12"
     cluster="m3eb.1b141aadc6200b12"
     cluster_size="2626 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="browsefox riskware ocna"
     md5_hashes="['0a6b2789f6aae1b0893a9baf24ff0da5', '01fac97f0d45b78f14b675ae256c900a', '03025cf5f012c15422d14b68ca00de05']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(118272,256) == "eba35edfca18ae78ba7fd9f9cd5e2659"
}

