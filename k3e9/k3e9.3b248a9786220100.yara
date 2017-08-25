import "hash"

rule k3e9_3b248a9786220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b248a9786220100"
     cluster="k3e9.3b248a9786220100"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a62636926fc49815f40a38d7760e2767', 'c3606ac810c0175354f968bd4978d6d8', '4c34122b58b2ead1bbe30183b5176652']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b98c324b2bff1dc76c923acdf9437671"
}

