import "hash"

rule o3e9_153bac6aded249b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.153bac6aded249b2"
     cluster="o3e9.153bac6aded249b2"
     cluster_size="316 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['cbdbc3956e02e7c6023b66539f7a5ee0', 'd5726d3b11b11ee63f83bcd34dce054b', '4d935e97bd66052450d65257b39da71d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2642696,1028) == "50885f8e31e78f0e123ef2b6a00f279d"
}

