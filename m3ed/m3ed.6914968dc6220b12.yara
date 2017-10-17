import "hash"

rule m3ed_6914968dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6914968dc6220b12"
     cluster="m3ed.6914968dc6220b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d8966bd27c5513bf51416209faa1dbb6', 'c155fa90fc5baf59be18573bfa120a66', 'a56b506ef13a37581d21449deaea9728']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24576,1024) == "b6d13ad924b068c5d54402f66b3811d7"
}

