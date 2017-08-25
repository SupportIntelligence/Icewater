import "hash"

rule k3e9_6b64d34b8a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a4b4912"
     cluster="k3e9.6b64d34b8a4b4912"
     cluster_size="144 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c4fd2b05e1c8d596304f22b46f9dfab6', 'fb84448c946ae8de085d45ff137d3442', '8c111e5e38082aa66fd322e1fbaa68f1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

