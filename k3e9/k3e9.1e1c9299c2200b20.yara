import "hash"

rule k3e9_1e1c9299c2200b20
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e1c9299c2200b20"
     cluster="k3e9.1e1c9299c2200b20"
     cluster_size="213 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c7d86f09baf409975b76854e87cb3efb', 'ea6f50323b41f9d02745a774e29a4989', 'c1ccf016fc819e9711c64519b50541ce']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,256) == "a9ab0e558550d293cb5457a10fc3049b"
}

