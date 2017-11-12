import "hash"

rule k3e9_2918f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2918f3e9c8000b12"
     cluster="k3e9.2918f3e9c8000b12"
     cluster_size="88 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor simbot"
     md5_hashes="['4262c68a2bc075542e1ac1e63a4a49b5', 'dec69f69c2a48bdf9ab7457c769ce060', '4340ea8c259775b470f38755122c4a01']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

