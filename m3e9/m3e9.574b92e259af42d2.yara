import "hash"

rule m3e9_574b92e259af42d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.574b92e259af42d2"
     cluster="m3e9.574b92e259af42d2"
     cluster_size="8151 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0a51eba11110e3ce642388ad5fbb1ee7', '0c55d941f9760ade71e74b5d6757601c', '0d305d1f51f23086c5fd6ecd10179b5c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(109392,1024) == "4f9b1295edcebadbd9c73c09cd7bcc4e"
}

