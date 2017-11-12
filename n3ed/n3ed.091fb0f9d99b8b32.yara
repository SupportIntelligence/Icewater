import "hash"

rule n3ed_091fb0f9d99b8b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9d99b8b32"
     cluster="n3ed.091fb0f9d99b8b32"
     cluster_size="453 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a6f2786f3e136626d443fba3d246e19b', '4bcf2655ca1577f6ed4c7e6da6ad66c0', 'b624403801c616ff0e176547d605fa1e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

