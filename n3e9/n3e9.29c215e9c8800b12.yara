import "hash"

rule n3e9_29c215e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c215e9c8800b12"
     cluster="n3e9.29c215e9c8800b12"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe trojandropper"
     md5_hashes="['deb208c1617f06f1ac62d180102bf503', 'e081345e923ded5f4c72caac65866819', 'b2df8dc596f0b9946bb78e356396cca9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413184,1076) == "ab5c78a222b72df8502930b7c2966067"
}

