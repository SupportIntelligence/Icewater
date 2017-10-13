import "hash"

rule m400_14ba7048c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.14ba7048c0000932"
     cluster="m400.14ba7048c0000932"
     cluster_size="886 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy hupigon backdoor"
     md5_hashes="['57573391917ab9218aab87cc6954a5e5', '101639182dc3a3f88340f67c0131e82f', '68ca8e1be903b370f9c096caca5de626']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74582,1081) == "92e4d80b0ee2c5027e00d0973e66e3ad"
}

