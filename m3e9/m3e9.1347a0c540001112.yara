import "hash"

rule m3e9_1347a0c540001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1347a0c540001112"
     cluster="m3e9.1347a0c540001112"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik malicious"
     md5_hashes="['585283f09ff8ccb3d36ed861d6d698db', 'e47b7763bbd6488d61a0d082c0b388c8', '0b17f56da26d41fa04a19b74b18fc181']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(67044,1052) == "4420c519b75f9b12079ab50a22acfc28"
}

