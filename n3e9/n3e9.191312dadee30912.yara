import "hash"

rule n3e9_191312dadee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.191312dadee30912"
     cluster="n3e9.191312dadee30912"
     cluster_size="7880 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vbkrypt manbat injector"
     md5_hashes="['016618860c8a7c70c5fe1b6dc7fa0a23', '0fba5e7391016c235fd00a3ad99c800a', '06cf3571968957f1d887663a1ac0211d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(398336,1024) == "ac4c406ac6ab743068339498fb9607ab"
}

