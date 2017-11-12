import "hash"

rule k3e9_5feb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5feb149bda2303b2"
     cluster="k3e9.5feb149bda2303b2"
     cluster_size="546 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre malicious kryptik"
     md5_hashes="['a8c253f440c2bcb5cf423d2d0495d1ed', 'ad080d0e8e77d8ce90ca98f24bdb7c1c', 'b1b33caff5b46cd3ae908d20f9d0edde']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14336,1024) == "f4c70291aad6b8a3bffea05c89b45f7f"
}

