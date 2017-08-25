import "hash"

rule k3e9_4324f856d992e113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856d992e113"
     cluster="k3e9.4324f856d992e113"
     cluster_size="262 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a8967fe8388f31fbba51281333e2718a', 'cdd6e851a4a0a6b745a1f26a4bc6912a', 'be6b0b332e73dc2c3f0b7c41d4612a8b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "a5658a555b991c738a328ec7df4c12bc"
}

