import "hash"

rule n3ed_311c6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.311c6a49c0000b12"
     cluster="n3ed.311c6a49c0000b12"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['908622990521173ee8e1e8aafaa6d75c', 'c1978998b5890ab456fecd7c8f239b70', '908622990521173ee8e1e8aafaa6d75c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "5c4a589b16d2a1290e4e4649ff07c622"
}

