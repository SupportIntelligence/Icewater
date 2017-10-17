import "hash"

rule m3e9_6934c84addcf4932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6934c84addcf4932"
     cluster="m3e9.6934c84addcf4932"
     cluster_size="88 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef wbna"
     md5_hashes="['3577e02dda587034f1116649ca9bea6d', 'be096f69d454928d46577c9f4a4848b3', 'c5546b3aba6b085bee00e0e70fd8ebc6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(189440,1024) == "ae6b32f183c232759d4af84e8be5e21a"
}

