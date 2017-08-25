import "hash"

rule k3e9_6b64d36b996b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b996b5912"
     cluster="k3e9.6b64d36b996b5912"
     cluster_size="198 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['0dd176f547507ffcdc9f7ee75ec7f41e', 'd7a0fa7871421cbd2145322eec3f8ec2', 'b4f803bf76a77bcf657f826360831fa5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

