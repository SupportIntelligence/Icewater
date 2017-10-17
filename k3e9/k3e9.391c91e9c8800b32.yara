import "hash"

rule k3e9_391c91e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c91e9c8800b32"
     cluster="k3e9.391c91e9c8800b32"
     cluster_size="101 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c06dbdf0f29f7f3ab0d65b98702c9e50', '0975e0179bfefc9b7ecef678a748dbab', 'a89d4f454d2b78b34f02ad3dff1c296f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "482beaebbdc1ed3d7533b440ec3ba87c"
}

