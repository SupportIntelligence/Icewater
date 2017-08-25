import "hash"

rule k3e9_125a9299c2200b20
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.125a9299c2200b20"
     cluster="k3e9.125a9299c2200b20"
     cluster_size="71 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e802e731e0096bc88019f934e47bfce3', 'a2aa2b641f584ddb38850b0205ec7142', 'b2ace1b22a1795e5a6dd1c3ccaa12a3b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9216,1024) == "5e1f5574dfff7e1b891594910b6ed454"
}

