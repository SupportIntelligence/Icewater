import "hash"

rule o3e7_199ce448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.199ce448c0000b12"
     cluster="o3e7.199ce448c0000b12"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious black engine"
     md5_hashes="['b53672c25d87ec00c3b2b9c8e4204696', '28fa703200f133934e077fc9d167777a', 'c6103fefd05bd425453e3394aaea1ab4']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1024,1024) == "72c639603b500a7dfa3149b86f050828"
}

