import "hash"

rule m3e9_32cb22554cee5aba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32cb22554cee5aba"
     cluster="m3e9.32cb22554cee5aba"
     cluster_size="61 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup kazy gepys"
     md5_hashes="['b7facd56f9ffc7103e4784fa562d829f', '47fd26490211c3c590486abe0471dbd6', 'a5f0e508e7d869f13914b92a707b4ef2']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(237056,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

