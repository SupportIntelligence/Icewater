import "hash"

rule m3ec_013ebd49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.013ebd49c0000912"
     cluster="m3ec.013ebd49c0000912"
     cluster_size="3080 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="antavmu fileinfector squdf"
     md5_hashes="['5f620d644e292ac4ce22e4162dba572b', '95143d16a003521cc66b911e3aaee999', '07c00a8f7e1e723dceea77a7cfee49c5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(49664,1024) == "028cdc1b0446e95fe56a081d75687e5a"
}

