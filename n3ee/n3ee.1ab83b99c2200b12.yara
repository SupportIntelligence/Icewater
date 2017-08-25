import "hash"

rule n3ee_1ab83b99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ee.1ab83b99c2200b12"
     cluster="n3ee.1ab83b99c2200b12"
     cluster_size="8990 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="chem snarasite malicious"
     md5_hashes="['06508edbdef4f9374eff7f4da2301c72', '07a3f9c5d6a940e9563e1823d15a02d2', '022c50e64c003533ce530f7ba4129d4f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(442368,1024) == "5d5bd7d8215887b4ffefa6784f8f65cb"
}

