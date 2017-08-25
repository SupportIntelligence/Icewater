import "hash"

rule k3e9_63146db11d927b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146db11d927b16"
     cluster="k3e9.63146db11d927b16"
     cluster_size="114 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b0eabaaf6f8cf5108ccf726fd4b35fed', 'c0ff6ef591e6bf495a1d3c5dc6d34416', 'f0881e184de9b22b6fe9305e2fe4a918']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

