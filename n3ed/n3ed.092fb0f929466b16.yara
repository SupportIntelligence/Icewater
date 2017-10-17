import "hash"

rule n3ed_092fb0f929466b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.092fb0f929466b16"
     cluster="n3ed.092fb0f929466b16"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b2d3ee4589d57841f98d6664cb65a97c', '9a6809bb3d6946dbc2e92d8fa867a22f', 'c05c082da9d8dbd98554591e673fed6a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

