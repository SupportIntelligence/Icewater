import "hash"

rule k3e9_4324f856cc4ae113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856cc4ae113"
     cluster="k3e9.4324f856cc4ae113"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a2bc152266d3fe81e6f3de908ad27592', 'dab5d5e89789f10f8cc8a5cbe097b85a', 'a2bc152266d3fe81e6f3de908ad27592']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17840,1051) == "51b64a94180b51b8ca3674839412385e"
}

