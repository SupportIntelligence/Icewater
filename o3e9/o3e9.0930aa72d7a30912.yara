import "hash"

rule o3e9_0930aa72d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0930aa72d7a30912"
     cluster="o3e9.0930aa72d7a30912"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="pwsime rootkit malicious"
     md5_hashes="['204ca9af3ee5b0db99aaefc479b6e676', '7acf9cabef0f7a2faa1add7edff5970e', '49e009d4d9fc017d4959f4632c7ed73a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1935360,1024) == "818099ef86babdb779045a243952568c"
}

