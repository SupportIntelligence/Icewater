import "hash"

rule n3e9_6c18dbb8c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6c18dbb8c8800b32"
     cluster="n3e9.6c18dbb8c8800b32"
     cluster_size="4299 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="bxqw ainslot shakblades"
     md5_hashes="['14f68b83a06a13e65093d6369d4d5656', '0305989d542e850fd88967b061436ede', '1ac9db0ab7bbe98ae03e4e5298b45e01']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(417792,1024) == "15572558512363aafa0609e94f90362e"
}

