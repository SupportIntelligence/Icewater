import "hash"

rule k3e9_17e34e961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e34e961ee31132"
     cluster="k3e9.17e34e961ee31132"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a8c2d9e322a8f81e58560923540d0ab3', '92ef88589f8f34e4a96cc83eaefcb575', 'a8c2d9e322a8f81e58560923540d0ab3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19200,256) == "3b15958506c859264d98a47823d86ece"
}

