import "hash"

rule k3e9_222cae39c29a9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.222cae39c29a9912"
     cluster="k3e9.222cae39c29a9912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor qukart berbew"
     md5_hashes="['e44b78ff46203808ae0ca0b43ce600a8', 'a5a939214f5fae5a9a439ae0d987d6f7', 'cd8b53da706c052d143392b0a922326c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

