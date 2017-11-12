import "hash"

rule k3e9_139ce164ddb39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce164ddb39932"
     cluster="k3e9.139ce164ddb39932"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ce86d8c8cd480f015fbb4fe6e82c89fe', 'ea5eca9b7fd75d3e6a830840d5cc8f2e', 'afef667402aede69a52a9b122781578b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

