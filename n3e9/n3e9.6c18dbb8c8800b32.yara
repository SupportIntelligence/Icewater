import "hash"

rule n3e9_6c18dbb8c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6c18dbb8c8800b32"
     cluster="n3e9.6c18dbb8c8800b32"
     cluster_size="4390 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="bxqw ainslot shakblades"
     md5_hashes="['169e265a1104c00c07ca44c3a0420ac4', '0042eb734d0d495b21deb3765b660c55', '062b69c924a2ae16b00ca5d1c31a92b3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(417792,1024) == "15572558512363aafa0609e94f90362e"
}

