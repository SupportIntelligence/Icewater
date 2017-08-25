import "hash"

rule k3e9_331c1499c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.331c1499c2200b00"
     cluster="k3e9.331c1499c2200b00"
     cluster_size="173 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d85537c915fb977b8888ae14be927f49', 'd85537c915fb977b8888ae14be927f49', 'd3ee4e08dd85ac1b98e55e57f74c6f8e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9216,1024) == "3cd74ec5a97434d76724b507d80be74e"
}

