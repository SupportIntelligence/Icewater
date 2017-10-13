import "hash"

rule n3e9_39c21569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c21569c8800b12"
     cluster="n3e9.39c21569c8800b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper backdoor"
     md5_hashes="['af18b19dbf1b8cd8975a3387186a1df8', '7e7ef207eba9b5355e0eee72ce454d2a', 'b4fbeac867c3e5ae339cf17a64c70829']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413696,1076) == "ab5c78a222b72df8502930b7c2966067"
}

