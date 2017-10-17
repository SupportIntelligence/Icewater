import "hash"

rule o3e9_29e3a3a9c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29e3a3a9c0000932"
     cluster="o3e9.29e3a3a9c0000932"
     cluster_size="414 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     md5_hashes="['0d4f69120a876fcc1bd117b38cbdde33', '1a34afc7ac90c763cbb4dbd65a8291bb', '56a192071eeec14d39017750b77f6cb2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(814080,1024) == "31a7d74b920a3fef0c87d0f24c8f6b2c"
}

