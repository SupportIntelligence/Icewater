import "hash"

rule o3e9_6c05ea49c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6c05ea49c4000932"
     cluster="o3e9.6c05ea49c4000932"
     cluster_size="150 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cnmb startsurf malicious"
     md5_hashes="['f10805d5be9d039718243551d92375ed', '9ef91d3acbd89a30cb5c2e772d1580e7', '46a5e2c18ff8f448d70d3469ff8945ba']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(395776,1024) == "0ebe41a3c088049b5fd8cf599def955b"
}

