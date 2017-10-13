import "hash"

rule n3e9_3a1b1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3a1b1cc1cc000b12"
     cluster="n3e9.3a1b1cc1cc000b12"
     cluster_size="46927 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="qakbot midie backdoor"
     md5_hashes="['018ec1686ef1fb29de703563aab5fe64', '000d0b92fc435c949c5b0c865f12f7dc', '00d4e9d6f499604ba931931281b00047']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(249168,1040) == "be1b1c491c7ae92fdca281284ec386f9"
}

