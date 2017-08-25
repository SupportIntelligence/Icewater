import "hash"

rule k3e9_5c66aad7c2220120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5c66aad7c2220120"
     cluster="k3e9.5c66aad7c2220120"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['8f59efa28a314e72d08dbd56d11600aa', '8f59efa28a314e72d08dbd56d11600aa', 'c748c98987d3121495d9b4ce990f18e9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "76f94909e41b2606eb664d22a535c8d2"
}

