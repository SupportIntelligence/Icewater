import "hash"

rule k3e9_4324f856ce12e112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856ce12e112"
     cluster="k3e9.4324f856ce12e112"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a46c0d731a930fdcb72fcece3a9b3049', 'cddd9546dc05bad036786657656a4d59', 'a46c0d731a930fdcb72fcece3a9b3049']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17840,1051) == "51b64a94180b51b8ca3674839412385e"
}

