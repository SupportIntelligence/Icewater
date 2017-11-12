import "hash"

rule k3e9_05315856dcbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05315856dcbb1932"
     cluster="k3e9.05315856dcbb1932"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a4e9262caf806038588370d619a89d91', 'a1572caf6cae22a082fda0c6a48a5c72', 'd2e6d739b617187ff4bab4de3564eb64']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

