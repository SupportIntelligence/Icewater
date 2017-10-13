import "hash"

rule n3ed_53166a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53166a48c0000b16"
     cluster="n3ed.53166a48c0000b16"
     cluster_size="895 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a0c11c93c3d047e3b6a2fd6d91296937', '9b80455bc5bdc1eccf73f4a73cac61e0', 'a21b1dc5639c5fa0a602c75580843e0c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

