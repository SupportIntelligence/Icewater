import "hash"

rule m3e9_6b345ec3ee008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b345ec3ee008932"
     cluster="m3e9.6b345ec3ee008932"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e29d2f9eb7c8fd973ec2218338daf823', 'b229a1b4485cea4df9e3550f400039c3', '89b26cd69f39d4de9761745a9361cd1d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(112640,1024) == "05684ba4ec00e21eee214300714771d5"
}

