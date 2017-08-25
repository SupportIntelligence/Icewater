import "hash"

rule k3e9_51b93316dda30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93316dda30932"
     cluster="k3e9.51b93316dda30932"
     cluster_size="164 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bc6126f854894534d88ff6c41727d8fd', 'e704f2bb30047bdea11ee644f3b9c170', '5a585a1845b860d81f1b9f9cd7766829']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4864,256) == "a123699e38ecb694dc0255cec9d6cbbb"
}

