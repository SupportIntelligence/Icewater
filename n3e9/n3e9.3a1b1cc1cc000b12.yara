import "hash"

rule n3e9_3a1b1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3a1b1cc1cc000b12"
     cluster="n3e9.3a1b1cc1cc000b12"
     cluster_size="61294 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qakbot midie backdoor"
     md5_hashes="['05d1259b77db98c0357303424e248bea', '077e02dc87fc2f276211cc79c8732f42', '0595197c396a74613684af868cf41751']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(249168,1040) == "be1b1c491c7ae92fdca281284ec386f9"
}

