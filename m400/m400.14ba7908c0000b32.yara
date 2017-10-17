import "hash"

rule m400_14ba7908c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.14ba7908c0000b32"
     cluster="m400.14ba7908c0000b32"
     cluster_size="54 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hupigon razy backdoor"
     md5_hashes="['56c4e271ac81c1991bb85f3911d946d5', 'a0f955e579044dc81d1ac2d56d4c5b25', 'b88dabbf373f59203bd7e64a38e10bb8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74070,1081) == "92e4d80b0ee2c5027e00d0973e66e3ad"
}

