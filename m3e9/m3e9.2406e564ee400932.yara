import "hash"

rule m3e9_2406e564ee400932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2406e564ee400932"
     cluster="m3e9.2406e564ee400932"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['8d177d83ca22f7e9c681d938cf907558', 'a5981d1a1d500e43d4876dd02dcbeba0', '43ad431c766f23b80aacff39ffd00a10']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(76800,1280) == "1aff12a5de171faf407903c639ca9a4c"
}

