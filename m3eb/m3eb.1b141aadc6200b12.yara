import "hash"

rule m3eb_1b141aadc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3eb.1b141aadc6200b12"
     cluster="m3eb.1b141aadc6200b12"
     cluster_size="2651 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="browsefox riskware ocna"
     md5_hashes="['0e2a56b81c34718e14c29f2eb82f020a', '136220f77070be800ce16304658f5e2d', '0ef6babe70a415598ff9bde4125cb8d9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(118272,1536) == "b2f443d1503cfb14977b79b52312367b"
}

