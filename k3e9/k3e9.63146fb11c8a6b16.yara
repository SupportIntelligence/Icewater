import "hash"

rule k3e9_63146fb11c8a6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11c8a6b16"
     cluster="k3e9.63146fb11c8a6b16"
     cluster_size="51 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ba0ac0ac3b9d247ca8eb241db742f19f', 'e6ddf3cfe3881fe2a4d4a95bdbef783e', 'b1ce4f625a1648011d5ac019cc052efd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

