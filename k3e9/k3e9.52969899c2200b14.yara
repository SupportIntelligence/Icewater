import "hash"

rule k3e9_52969899c2200b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52969899c2200b14"
     cluster="k3e9.52969899c2200b14"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2752c80998d22163e33b3f263ca14226', '2752c80998d22163e33b3f263ca14226', '0323d7074facef95b0e59549e49e0fb4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "eb80058900d487bd112d18ba2a5781d1"
}

