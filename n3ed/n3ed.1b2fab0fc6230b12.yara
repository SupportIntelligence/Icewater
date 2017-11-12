import "hash"

rule n3ed_1b2fab0fc6230b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fab0fc6230b12"
     cluster="n3ed.1b2fab0fc6230b12"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ddf0ac2c6695d58728ac79ac8e9d4f4c', 'ddf0ac2c6695d58728ac79ac8e9d4f4c', 'cabb8c909efd059505c35913a5c67648']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "f3e36befd0755f24ecffaff8a4db5c6e"
}

