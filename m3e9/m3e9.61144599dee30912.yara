import "hash"

rule m3e9_61144599dee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61144599dee30912"
     cluster="m3e9.61144599dee30912"
     cluster_size="102 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus barys autorun"
     md5_hashes="['c87ccb49bd76a29817313856611ef87a', 'c87ccb49bd76a29817313856611ef87a', 'dd4bf181ba253682816018dac5ba6bf1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(143360,1024) == "801b4bb5350c198135a49b30c0501503"
}

