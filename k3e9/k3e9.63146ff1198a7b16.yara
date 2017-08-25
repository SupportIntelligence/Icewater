import "hash"

rule k3e9_63146ff1198a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff1198a7b16"
     cluster="k3e9.63146ff1198a7b16"
     cluster_size="49 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c7acc71ea33f773fdabec64e811a0ca8', 'c1a279a33036433ca80a1f0d1e2438a4', 'b24b94cbadc4f048862e2ea6ecfe2f2f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

