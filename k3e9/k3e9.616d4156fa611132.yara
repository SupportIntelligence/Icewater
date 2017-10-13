import "hash"

rule k3e9_616d4156fa611132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.616d4156fa611132"
     cluster="k3e9.616d4156fa611132"
     cluster_size="1592 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre waski generickd"
     md5_hashes="['4f0aa1e3afd754d3562f28d5a30e7de2', '6ce6cc9a43fb6bcd494bcdc74b37f2bb', '244a764cc5c5ba904685db1f6c860877']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "a8a8e794c969ee03d14a49581e6e0204"
}

