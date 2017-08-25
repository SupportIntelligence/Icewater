import "hash"

rule o3e7_0b315ad2ef06d311
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0b315ad2ef06d311"
     cluster="o3e7.0b315ad2ef06d311"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="dlboost malicious engine"
     md5_hashes="['a4af0cc17bfc5c2d20cbb5a591bda5e7', 'a4af0cc17bfc5c2d20cbb5a591bda5e7', '50a0e7cb38379158a46c4dc6fe7bccf4']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1762072,1025) == "bcbe238a0a995e1087ad0a03dec3f6f8"
}

