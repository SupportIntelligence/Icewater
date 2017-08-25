import "hash"

rule k3e9_17e315961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e315961ee31132"
     cluster="k3e9.17e315961ee31132"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['f31b5eb0329510f670c789c9d6e8a179', 'cca42851bfce435f9c83d45caf04ba2c', 'cca42851bfce435f9c83d45caf04ba2c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

