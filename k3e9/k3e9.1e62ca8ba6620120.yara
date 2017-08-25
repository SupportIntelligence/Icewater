import "hash"

rule k3e9_1e62ca8ba6620120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e62ca8ba6620120"
     cluster="k3e9.1e62ca8ba6620120"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a1ab0f76293a2ea1015e55efc0d6d390', 'a1ab0f76293a2ea1015e55efc0d6d390', 'a1ab0f76293a2ea1015e55efc0d6d390']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b98c324b2bff1dc76c923acdf9437671"
}

