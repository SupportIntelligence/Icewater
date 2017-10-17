import "hash"

rule n3ed_091fb0f9c9369b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c9369b32"
     cluster="n3ed.091fb0f9c9369b32"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d11bf4f70c782a2e195464dc21fed65d', '2c5ccd29aa557d1866abf57f149927c3', 'b0e23962315f21c6006be30de667ff03']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(557568,1536) == "b9cda3dc6312066652120fdbfdef49d4"
}

