import "hash"

rule o3ed_635244cece427b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece427b16"
     cluster="o3ed.635244cece427b16"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a7b9810064b4a6cbef031a17cc751e54', 'e421dbdbab4264f33ced49f7262eb7f2', '3d691277a0cd33099fe3c15c50d67ebc']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2779136,1024) == "9e9ec715484cb1af8b99faa9662b062c"
}

