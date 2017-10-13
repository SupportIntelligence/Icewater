import "hash"

rule m3e7_211c3949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.211c3949c0000b32"
     cluster="m3e7.211c3949c0000b32"
     cluster_size="284 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['c36b4ec092391744c4c3e2ee57a22563', '49b259d86a57e7d64d3fc70136ae5695', 'c39515234018d677b1307ece711af280']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62090,1058) == "2cc91028f6f559f9c633c41bba0674cd"
}

