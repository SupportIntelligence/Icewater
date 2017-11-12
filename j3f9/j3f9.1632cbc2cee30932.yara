import "hash"

rule j3f9_1632cbc2cee30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.1632cbc2cee30932"
     cluster="j3f9.1632cbc2cee30932"
     cluster_size="24219 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bdmj memscan flooder"
     md5_hashes="['0961d99d65fd2339f0b414591f94ceac', '03292fa5f3f3a113bf4b31bf94cf15e4', '07e8496cb8feceef3ba8f6e562c2c89d']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(7168,1305) == "389970a4cbc0b560a2df71cc9856c3fb"
}

