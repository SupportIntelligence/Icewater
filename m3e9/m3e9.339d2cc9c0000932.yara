import "hash"

rule m3e9_339d2cc9c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.339d2cc9c0000932"
     cluster="m3e9.339d2cc9c0000932"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="scar zusy popureb"
     md5_hashes="['c4bd1ec930e2e8cc628ccef42a1aec7b', 'b411ed654245032a7d154be43352273a', 'a6957a39d370e1e19ce87c5a492db0f4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(33792,1024) == "94a4442dad071ee5823b83017410b53c"
}

