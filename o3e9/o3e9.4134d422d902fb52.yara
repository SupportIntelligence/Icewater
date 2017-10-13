import "hash"

rule o3e9_4134d422d902fb52
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4134d422d902fb52"
     cluster="o3e9.4134d422d902fb52"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wannacry wannacryptor"
     md5_hashes="['a75a57a712300662ce3ff1447a0c4805', 'a75a57a712300662ce3ff1447a0c4805', 'a75a57a712300662ce3ff1447a0c4805']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(40960,1024) == "e27288d0485e382bc67cd82ed066ecfa"
}

