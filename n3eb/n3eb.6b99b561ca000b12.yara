import "hash"

rule n3eb_6b99b561ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3eb.6b99b561ca000b12"
     cluster="n3eb.6b99b561ca000b12"
     cluster_size="1305 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="runbooster susp siggen"
     md5_hashes="['2b26ba312b4497dc653b757243d04b62', '1c7a2b5c9258a54d99daa84cb94ab141', '3972c0e53a72574f62806dd234b7caa1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(371712,1024) == "a9e2a4864ec157f2fc849688f143eb18"
}

