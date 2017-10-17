import "hash"

rule k3f4_0c3269c2d1a34952
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.0c3269c2d1a34952"
     cluster="k3f4.0c3269c2d1a34952"
     cluster_size="420 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox msilperseus yontoo"
     md5_hashes="['3a61a86d4e71fc2c9207f3505e28b25e', '83d01351819fb54b54ac9a7e9134ce14', '66059bc0b8f17312757f5088554b766c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(57344,1536) == "691afa3c7ed4daf6e7433dd1ef89157c"
}

