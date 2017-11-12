import "hash"

rule k3e9_033ca619da9b9916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.033ca619da9b9916"
     cluster="k3e9.033ca619da9b9916"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="berbew qukart backdoor"
     md5_hashes="['a52309d31ef437ec2395b12f1e045234', 'b707d4e5d2bec031522642c8d911fb1e', 'b707d4e5d2bec031522642c8d911fb1e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

