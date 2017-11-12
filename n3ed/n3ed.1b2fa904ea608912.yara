import "hash"

rule n3ed_1b2fa904ea608912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa904ea608912"
     cluster="n3ed.1b2fa904ea608912"
     cluster_size="46 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cec5ed0d896545c313ac8c115fb860ab', 'b09a94d6e7aaf14940edb2626cd3e444', 'af33838744a5b625f0e8bfdef12c4585']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(318976,1024) == "e261aea59281d743ef2c1a004d20b295"
}

