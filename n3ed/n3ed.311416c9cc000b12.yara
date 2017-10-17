import "hash"

rule n3ed_311416c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.311416c9cc000b12"
     cluster="n3ed.311416c9cc000b12"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['b077fb595e750b6436f711d4528528a6', 'a9c90506f7867b9f3a4ff6d98e9b9d40', 'a3433adeabb62b3a73f8a69e65b99afc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

