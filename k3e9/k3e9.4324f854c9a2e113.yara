import "hash"

rule k3e9_4324f854c9a2e113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f854c9a2e113"
     cluster="k3e9.4324f854c9a2e113"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['baf6f23bc7e5dd0b4d66d0ad69e6ba15', 'baf6f23bc7e5dd0b4d66d0ad69e6ba15', 'baf6f23bc7e5dd0b4d66d0ad69e6ba15']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17840,1051) == "51b64a94180b51b8ca3674839412385e"
}

