import "hash"

rule n3e9_191312dadee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.191312dadee30912"
     cluster="n3e9.191312dadee30912"
     cluster_size="28273 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt manbat injector"
     md5_hashes="['047db75c81e7669089ea61cecc7c19ce', '0810b643eb2b6d043651883a4c7b6556', '0673a84e6bc9b53f8e4dd3e5a341bcd8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(398336,1024) == "ac4c406ac6ab743068339498fb9607ab"
}

