import "hash"

rule k3e9_1e1c1299c2200b20
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e1c1299c2200b20"
     cluster="k3e9.1e1c1299c2200b20"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['da596fad5321fb05232cd7b85ee549dd', '80cc95c76cb65c4c5d9343f2049d047c', 'd875bba69985567f1d7ee716e75a11f3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "8faf88ffd3631e972f6bce255f7c9fef"
}

