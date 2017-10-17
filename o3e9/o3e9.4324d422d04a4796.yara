import "hash"

rule o3e9_4324d422d04a4796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4324d422d04a4796"
     cluster="o3e9.4324d422d04a4796"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wannacry wannacryptor"
     md5_hashes="['6ede51472aa29b9f77849f00d04a2c67', '6ede51472aa29b9f77849f00d04a2c67', '6ede51472aa29b9f77849f00d04a2c67']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(40960,1024) == "e27288d0485e382bc67cd82ed066ecfa"
}

