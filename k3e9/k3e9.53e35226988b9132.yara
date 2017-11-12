import "hash"

rule k3e9_53e35226988b9132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53e35226988b9132"
     cluster="k3e9.53e35226988b9132"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['0b51c054249b3612fd63d6c4fee5432e', '0b51c054249b3612fd63d6c4fee5432e', '0b51c054249b3612fd63d6c4fee5432e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(4096,1024) == "9501dbdb314d29c7e56b61336dc716cb"
}

