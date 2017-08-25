import "hash"

rule k3e9_17e30c961ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30c961ee311b2"
     cluster="k3e9.17e30c961ee311b2"
     cluster_size="7 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9a98d197fe9613ef8c2863564e53be2b', 'e35324115584d58f6f21f86ba7d3aea0', '18bac3884089d73284bb02fdca5c8157']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "c90aa5f283c5cb7bd8e6ffdf6a121846"
}

