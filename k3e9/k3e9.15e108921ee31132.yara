import "hash"

rule k3e9_15e108921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e108921ee31132"
     cluster="k3e9.15e108921ee31132"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a3ad8da084b89103300b048fd42e667f', 'c2e17c164123a930efd64a149a2031d2', 'a3ad8da084b89103300b048fd42e667f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8448,256) == "1e62b5fcfb3e134c6d1424488c1d6c5d"
}

