import "hash"

rule j3f0_1632cbc2cee30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.1632cbc2cee30932"
     cluster="j3f0.1632cbc2cee30932"
     cluster_size="24065 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bdmj memscan flooder"
     md5_hashes="['0474bc7579a774d8c209f325f2a3ae90', '05761b3609de5bbca013be66809263e9', '028b3f5a9ac2483f59a952f4878933ee']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(7168,1305) == "389970a4cbc0b560a2df71cc9856c3fb"
}

