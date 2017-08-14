import "hash"

rule k3e9_15e109521ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e109521ee311b2"
     cluster="k3e9.15e109521ee311b2"
     cluster_size="75 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['dd7b212aea033421fb3563020c4ca6e6', 'daf66d14f44bdf0d79eaf40296433ac7', 'c26e088f36826b02138e0bd330efd50a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8448,256) == "1e62b5fcfb3e134c6d1424488c1d6c5d"
}

