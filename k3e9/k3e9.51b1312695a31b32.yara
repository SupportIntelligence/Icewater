import "hash"

rule k3e9_51b1312695a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1312695a31b32"
     cluster="k3e9.51b1312695a31b32"
     cluster_size="96 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e41c380b0f3f62bbac2b14cb6362885d', 'b6dd3496ac806a77227eac0de8cc26c6', 'c91454f6123300067f3836f14ab0a1e2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

