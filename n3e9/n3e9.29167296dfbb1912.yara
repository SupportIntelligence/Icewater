import "hash"

rule n3e9_29167296dfbb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29167296dfbb1912"
     cluster="n3e9.29167296dfbb1912"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="icloader mikey dangeroussig"
     md5_hashes="['40e754ce979b8e00cf973f0ff1f67a41', '810c31a4b79b9440a9b3da434547f8dd', 'c957ffe5ebc87c2a432bffeec249eac7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "2a3cbe28e9575b0e98b3d828a8cbed73"
}

