import "hash"

rule m3e9_4d26ca9cd69949f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d26ca9cd69949f2"
     cluster="m3e9.4d26ca9cd69949f2"
     cluster_size="64 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="backdoor dialer zegost"
     md5_hashes="['48c07541c1955293b929070ca5709000', '07135bfc8a9d24fc44e0d671a83e17b4', 'f1aaf6385e4c577db3e161707ae4d638']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(25600,256) == "1b6edd298a2a51a46ae7f2cbe830610f"
}

