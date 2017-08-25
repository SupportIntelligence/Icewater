import "hash"

rule m3e9_43068399d37b8b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43068399d37b8b32"
     cluster="m3e9.43068399d37b8b32"
     cluster_size="11891 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="vbna deepscan cambot"
     md5_hashes="['08be598b83839827dc52d80f63c13e2e', '084f29204ae9757368a0e96131a55c5c', '078c730968c60e62d6241d441616d983']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(169984,1024) == "fe202617792d9ab58805761f29f3bf17"
}

