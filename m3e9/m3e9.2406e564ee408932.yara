import "hash"

rule m3e9_2406e564ee408932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2406e564ee408932"
     cluster="m3e9.2406e564ee408932"
     cluster_size="645 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2c17d58c03fd38fe2a99997f2a303295', '92a213e5e147e4c95c2ad76ba480114c', '18bdfadc2c98fce31b1fa582e153eb9f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(76800,1280) == "1aff12a5de171faf407903c639ca9a4c"
}

