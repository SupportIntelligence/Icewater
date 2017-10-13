import "hash"

rule n3ec_119599b9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.119599b9ca000b12"
     cluster="n3ec.119599b9ca000b12"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['552a0f7abbd8dbb6926d22552d59c119', '3a1989a51a2923b6aadbede47a85670c', 'cdbe7c66530b4142e17f522828a8b513']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410624,1024) == "297fcde3a8473f07462a33bd2acf4f6c"
}

