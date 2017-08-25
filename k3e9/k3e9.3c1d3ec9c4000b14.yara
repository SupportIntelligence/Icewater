import "hash"

rule k3e9_3c1d3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1d3ec9c4000b14"
     cluster="k3e9.3c1d3ec9c4000b14"
     cluster_size="153 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a3989d41ee227be3e20f43797d2f25db', 'ce80f4b857aa5e89d735649e0095cf41', 'a61a47b6bca23610c793f1b8a162518c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

