import "hash"

rule k3e9_6b64d34b996b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b996b4912"
     cluster="k3e9.6b64d34b996b4912"
     cluster_size="29 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a98b62ff5337822451e697b1dc033be8', 'ab08c563025629012be1dd911fb89106', 'bfb6828440421f7fa776362dc8400abf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

