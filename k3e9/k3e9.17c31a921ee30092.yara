import "hash"

rule k3e9_17c31a921ee30092
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17c31a921ee30092"
     cluster="k3e9.17c31a921ee30092"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cb15e3076fa1c7165bd55e6857fa5d30', 'b9eb2cc678a292103f003de48a0f8930', 'cb15e3076fa1c7165bd55e6857fa5d30']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "c90aa5f283c5cb7bd8e6ffdf6a121846"
}

