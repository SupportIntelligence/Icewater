import "hash"

rule m3f0_53e26a66ee630b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.53e26a66ee630b32"
     cluster="m3f0.53e26a66ee630b32"
     cluster_size="394 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup gepys kryptik"
     md5_hashes="['97d23bfcfb565e50e74d2a08f4920451', 'd2fcf86ba33298cf4986ba77111788d3', 'bb7685c68546633f3518684781db5422']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123392,1024) == "6f5f4a2694012881591c5c84e202174b"
}

