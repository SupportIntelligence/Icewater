import "hash"

rule n3e9_2b9632a2d7bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b9632a2d7bb1932"
     cluster="n3e9.2b9632a2d7bb1932"
     cluster_size="37 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kryptik malicious adload"
     md5_hashes="['52329c2c1228e66132a4664e97014ad8', 'd82d3003b1de6840e1ea68772bb89bee', '861fc1d9e863984d6dd8eed5cb52f1e0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(32768,1024) == "4f6d8e99032fc830ca959417276245a6"
}

