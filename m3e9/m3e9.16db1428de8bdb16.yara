import "hash"

rule m3e9_16db1428de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db1428de8bdb16"
     cluster="m3e9.16db1428de8bdb16"
     cluster_size="133 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cerber ransom zbot"
     md5_hashes="['b0174490c25bcdec2a1283acd6960914', 'b39edc96e133a668ebb06fcb53f5f549', 'b1c588e50ae1ebf2b7bb8fed2f579037']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27478,1194) == "93d2d5d08193ace1d2e321fae51a9d3f"
}

