import "hash"

rule k3e9_533ba316d6bb1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.533ba316d6bb1916"
     cluster="k3e9.533ba316d6bb1916"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['ac9f962776e1ecbc71dc6bfe77b36a43', 'ac9f962776e1ecbc71dc6bfe77b36a43', 'de849e71b48f05f0d556f9f23f47dd83']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12800,1280) == "9bec7913a2600fdf8cf39f32c8126b0b"
}

