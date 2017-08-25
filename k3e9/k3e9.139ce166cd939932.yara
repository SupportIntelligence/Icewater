import "hash"

rule k3e9_139ce166cd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce166cd939932"
     cluster="k3e9.139ce166cd939932"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['aaf08291d1c43d621ce692ed86d08290', 'c895e985844f0e29eb3c740037c0227d', 'c895e985844f0e29eb3c740037c0227d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

