import "hash"

rule k3e9_52bd941696c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd941696c31912"
     cluster="k3e9.52bd941696c31912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5a41c815062a4e5172cc9d1c4b953e27', '1852c14ba0404bc7963806b36a1bc7a6', '1852c14ba0404bc7963806b36a1bc7a6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "177790c0127a5a5ab5ac5824b96ec385"
}

