import "hash"

rule n3ed_1b2fa90cdee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa90cdee31912"
     cluster="n3ed.1b2fa90cdee31912"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cb3b056c5584b35c675cc215a9a4f4c2', 'a4f8c2fe2faf6c31b2cd4ad9f3c3b905', 'dc97a75d8c38c320e9592f72b1caeb2c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(318976,1024) == "e261aea59281d743ef2c1a004d20b295"
}

