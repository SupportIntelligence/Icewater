import "hash"

rule k3e9_4324d856d8bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324d856d8bb1912"
     cluster="k3e9.4324d856d8bb1912"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['f896004ea92fe2cb0a8a2d2eb2e7861a', 'bb9345789200e75a24ab420c0e48c62d', 'bb9345789200e75a24ab420c0e48c62d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "a5658a555b991c738a328ec7df4c12bc"
}

