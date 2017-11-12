import "hash"

rule o3e9_1539ac669ed2491e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1539ac669ed2491e"
     cluster="o3e9.1539ac669ed2491e"
     cluster_size="260 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['e95ece9cac950c3fe6771aa2630e2007', '11f143f4234fdda87303f181e80b162d', '727b18176c2ef932db2ed8bb0afb90a8']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(45056,1024) == "839d868e2fda3cc1039c990e6598b609"
}

