import "hash"

rule k3e9_053558569bbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.053558569bbb1932"
     cluster="k3e9.053558569bbb1932"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['9a820400b5929893eab2412607ffff6b', '181bb5acf4004e0bf4d689c634dc8d9a', 'c5a56be06c3bf7003e317f3abb3558d3']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

