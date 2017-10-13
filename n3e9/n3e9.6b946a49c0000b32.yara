import "hash"

rule n3e9_6b946a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6b946a49c0000b32"
     cluster="n3e9.6b946a49c0000b32"
     cluster_size="98 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="strictor sysn bzub"
     md5_hashes="['f7af5cb5b2ccccffbaf1e460f40230b5', '9300f80c1d48326ab7d49eed70466a1e', '939527a2b8e8d4510ef19d80338c4d10']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(42224,1030) == "9deda72ad97ffd9499b8971970e83cf8"
}

