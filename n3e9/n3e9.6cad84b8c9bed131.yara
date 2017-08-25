import "hash"

rule n3e9_6cad84b8c9bed131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6cad84b8c9bed131"
     cluster="n3e9.6cad84b8c9bed131"
     cluster_size="3832 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious adsearch attribute"
     md5_hashes="['039a9488f1381ba309b888d7207d089b', '015f5371a606d3a2bd588b1775652d3e', '0ed1d660d077b47905e06e49568edb9b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(790673,1053) == "cbf8242c53431a7d4e8885b8a6e3ff94"
}

