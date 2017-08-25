import "hash"

rule k3e9_3b24849782220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b24849782220100"
     cluster="k3e9.3b24849782220100"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['425646b0ca5ec236c0ce9843efc3a9e7', '09d84a68001d714ce81cfc3347d78be4', 'dd4ed4c6e1b0312573546cd6f6c0ef9c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "76f94909e41b2606eb664d22a535c8d2"
}

