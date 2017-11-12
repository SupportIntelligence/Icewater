import "hash"

rule m3e9_150a3ab9d9967392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.150a3ab9d9967392"
     cluster="m3e9.150a3ab9d9967392"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['50ea311837283427f1c7dec0044ec3dc', '50ea311837283427f1c7dec0044ec3dc', '74c544bb4125e2077f451474731f05f2']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(108544,1071) == "698123b4097303620115637265df5a66"
}

