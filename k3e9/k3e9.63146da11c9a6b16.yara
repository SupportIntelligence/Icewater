import "hash"

rule k3e9_63146da11c9a6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11c9a6b16"
     cluster="k3e9.63146da11c9a6b16"
     cluster_size="73 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a4aeff28852b8aa3573f9f08f339cbb2', 'ef2c638c6a369ad665fe7bdc4723e21b', '77615604a054e0bdf0e8ddbe36e424c4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

