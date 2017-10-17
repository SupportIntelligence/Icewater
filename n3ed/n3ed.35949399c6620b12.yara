import "hash"

rule n3ed_35949399c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.35949399c6620b12"
     cluster="n3ed.35949399c6620b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['b6085607dd501c372ed50559881f8603', 'b6085607dd501c372ed50559881f8603', 'b6085607dd501c372ed50559881f8603']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(180224,1024) == "7f8cd5586a514b80e6cbedb4eebfa148"
}

