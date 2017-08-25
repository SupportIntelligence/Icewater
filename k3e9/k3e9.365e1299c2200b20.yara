import "hash"

rule k3e9_365e1299c2200b20
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.365e1299c2200b20"
     cluster="k3e9.365e1299c2200b20"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['be39b43c96baf59eb4966846da889b56', 'a4c26746a96fe1ae0906d47a970d8595', 'c278258420ce84c906ed7f6440fa3644']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "8faf88ffd3631e972f6bce255f7c9fef"
}

