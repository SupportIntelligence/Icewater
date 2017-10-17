import "hash"

rule k3e9_4162d097ea601112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4162d097ea601112"
     cluster="k3e9.4162d097ea601112"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['b1d57d18723e385403e8227257154861', '0567c021a724fa748f003d4337b5e346', '0567c021a724fa748f003d4337b5e346']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12824,1048) == "fe5696cee63cd198395f8c2eb557b0b6"
}

