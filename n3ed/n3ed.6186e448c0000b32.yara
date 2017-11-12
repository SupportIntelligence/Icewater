import "hash"

rule n3ed_6186e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.6186e448c0000b32"
     cluster="n3ed.6186e448c0000b32"
     cluster_size="1134 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['66f2dc48bb903eac3c83eb4bdef1c2fd', 'a6e9fc885f8b7516bdf00141abc9f6e0', '47451606f3a7f0e0147e303859c89ac0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(159289,1081) == "938f05010c63059d0d482823f8969be6"
}

