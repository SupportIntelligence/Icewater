import "hash"

rule m3e9_2406e9748da91932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2406e9748da91932"
     cluster="m3e9.2406e9748da91932"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['506e590114e1e60e2e681ebcc36cbfe4', '77c34df287330edf05c22b6bb95a71d8', '2acfae4f21b8d3c15cb60a14b540744e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(76800,1280) == "1aff12a5de171faf407903c639ca9a4c"
}

