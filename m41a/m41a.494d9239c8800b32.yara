import "hash"

rule m41a_494d9239c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m41a.494d9239c8800b32"
     cluster="m41a.494d9239c8800b32"
     cluster_size="234 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="netfilter rootkit score"
     md5_hashes="['746160fb427f0247098d239b2218c59f', '9b1d2c8823e395f1e868ea3929c6ac72', '3f8c40541068e22b2bd3ed6cf99d76ac']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(102912,1024) == "8932c131501c0edce875077a50862b3b"
}

