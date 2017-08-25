import "hash"

rule k3e9_51b93326d3a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93326d3a31932"
     cluster="k3e9.51b93326d3a31932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a23a34a06169a08b46e6682079da258d', 'a23a34a06169a08b46e6682079da258d', '6c6a9993b0ef99d251a7ac873cc2d999']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "b64b84b038538c4ad2cc9e52262cbc46"
}

