import "hash"

rule k3e9_51b1331695a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1331695a31b32"
     cluster="k3e9.51b1331695a31b32"
     cluster_size="166 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b554a5e6258186694faff993c38290f1', 'ac684b7e982900a3f5ab6e8e13a81a00', 'a7b2052a6c310a73ea2346430ac2ebb9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "b64b84b038538c4ad2cc9e52262cbc46"
}

