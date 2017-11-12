import "hash"

rule n3e9_0db6538cda631932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0db6538cda631932"
     cluster="n3e9.0db6538cda631932"
     cluster_size="21999 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor injector kolab"
     md5_hashes="['0480d52a77c3a57479071be095dc95c9', '01c4babe4619dcef91d1e12b1c41502b', '05f20d293b589664e35c4476803e5b66']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(573440,1024) == "e70a449578de0ebe3d727addf93b4766"
}

