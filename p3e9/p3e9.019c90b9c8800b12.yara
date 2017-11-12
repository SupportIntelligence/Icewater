import "hash"

rule p3e9_019c90b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.019c90b9c8800b12"
     cluster="p3e9.019c90b9c8800b12"
     cluster_size="762 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy malicious ayzg"
     md5_hashes="['a2933124ec2d015eab9bae57c375d0b2', '375ede182e2afff7395e0f525e3fcbbd', 'a30744705f31915c81901228485db3e9']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(108544,1024) == "9650727afb29740793894269db598dc4"
}

