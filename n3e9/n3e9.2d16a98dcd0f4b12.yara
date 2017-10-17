import "hash"

rule n3e9_2d16a98dcd0f4b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2d16a98dcd0f4b12"
     cluster="n3e9.2d16a98dcd0f4b12"
     cluster_size="7019 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious adsearch downware"
     md5_hashes="['0192c12f054418513afa34fc2c061e0e', '0a6e3c0694d652491649659a4b55086c', '06992d503db178958d032023db115b03']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(721431,1047) == "16e31a3a63bb87d14b8e3ad78691e09c"
}

