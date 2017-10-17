import "hash"

rule k3e9_4324f854d902e113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f854d902e113"
     cluster="k3e9.4324f854d902e113"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ce0c26a6be6c8f5fd70f632f4765ec99', 'e1992a9a1566335d044da03e3d87db94', 'ce0c26a6be6c8f5fd70f632f4765ec99']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17840,1051) == "51b64a94180b51b8ca3674839412385e"
}

