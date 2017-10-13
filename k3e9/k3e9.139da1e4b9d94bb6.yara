import "hash"

rule k3e9_139da1e4b9d94bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da1e4b9d94bb6"
     cluster="k3e9.139da1e4b9d94bb6"
     cluster_size="228 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['a0e3037b276a47e8c292107277e9ed82', 'bcf017379f7e9d93a8843493e6eb3f4c', 'ae0e2fcb5395a850fd2431ae81b99ce2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

