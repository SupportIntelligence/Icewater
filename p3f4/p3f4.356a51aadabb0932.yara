import "hash"

rule p3f4_356a51aadabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f4.356a51aadabb0932"
     cluster="p3f4.356a51aadabb0932"
     cluster_size="393 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="riskware agentcrtd firq"
     md5_hashes="['aa148e9b9767cf5b540bbf17089860a6', 'a4dd7b558bb57658f64c3f655d53cd55', 'e0dd912b8a22c670eeaac43a9437ed42']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4029952,1024) == "71f9d1580c77419e956bd406a8dc2c98"
}

