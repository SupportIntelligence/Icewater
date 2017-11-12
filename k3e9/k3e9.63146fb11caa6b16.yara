import "hash"

rule k3e9_63146fb11caa6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11caa6b16"
     cluster="k3e9.63146fb11caa6b16"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c47e01ab96838167bc3c9ba5fad598b3', 'bdec91a4e27a7440ca639097b7009ff4', 'ca2b82bfc9e8d0113794a4df60895275']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

