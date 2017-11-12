import "hash"

rule k3e9_05355856ddbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05355856ddbb1932"
     cluster="k3e9.05355856ddbb1932"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['3a3c12054a655b8338ea2d94220062f8', '29c1ad7c32964d3194d831c531f4080b', '6aefb08f471cdd8d0cce0113ee1a6230']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

