import "hash"

rule m3e9_164b1ec9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.164b1ec9cc000932"
     cluster="m3e9.164b1ec9cc000932"
     cluster_size="114 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5722c257020a34622f8c4dfb9b47aa13', '2ba05af482888209dcd0e3f4562e2409', 'b142fb86854a6dc24d8a8c8e03700a5b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(29184,1536) == "cf692e5fbaebba02c2ad95f4ba0e60be"
}

