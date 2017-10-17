import "hash"

rule m3e9_54be7969d1bcc976
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.54be7969d1bcc976"
     cluster="m3e9.54be7969d1bcc976"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['9fe76403c2dd1a5c0d1cdd878229e0cf', 'c2f04319812c3c5f377cbbda46e20d64', '9fe76403c2dd1a5c0d1cdd878229e0cf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(75776,1024) == "a806624f3e0a2b0722e89b0892277d79"
}

