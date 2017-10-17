import "hash"

rule n3e9_29c690b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c690b9ca800b12"
     cluster="n3e9.29c690b9ca800b12"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt cuegoe trojandropper"
     md5_hashes="['c5cd246b41a6d80035cffed360db287d', 'd94f22833729aa173e36b14d7987d452', 'a02df7ff9e5c1d2e5837d15ad4392864']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433152,1076) == "ab5c78a222b72df8502930b7c2966067"
}

