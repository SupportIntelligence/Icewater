import "hash"

rule j3ec_46e316b9c8000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.46e316b9c8000132"
     cluster="j3ec.46e316b9c8000132"
     cluster_size="525 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fileinfector akes infector"
     md5_hashes="['44caa3bc79a8495641743105f81fbda1', '06b98c5bf9b225c30a5ba7ac7a8be28f', '13cc08644e0e35a7672f73e74c5a92a6']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(8704,1024) == "42e8489ac2cbb6cde11bc442a428e7fd"
}

