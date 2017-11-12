import "hash"

rule k3e9_139ca166dd839932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca166dd839932"
     cluster="k3e9.139ca166dd839932"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c023aa4c1fa4d964d25ad0b00d4f1d4a', 'e22b6c07d27ae7527646fe783530c549', 'bb5085684ce1e3a99bfd47d200dc376c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

