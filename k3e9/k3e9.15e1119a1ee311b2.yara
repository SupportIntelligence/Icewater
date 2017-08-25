import "hash"

rule k3e9_15e1119a1ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e1119a1ee311b2"
     cluster="k3e9.15e1119a1ee311b2"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d751b58c193f2bd8b9c800d343b8e303', 'd751b58c193f2bd8b9c800d343b8e303', 'd751b58c193f2bd8b9c800d343b8e303']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8448,256) == "1e62b5fcfb3e134c6d1424488c1d6c5d"
}

