import "hash"

rule k3e9_493e73049da31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e73049da31916"
     cluster="k3e9.493e73049da31916"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['1296df159c68345491ebde79d1c263d3', '5c5025c27d24e711e2ffb915b9cb540b', 'e4c2018decd2ad88719bba2c7185209b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

